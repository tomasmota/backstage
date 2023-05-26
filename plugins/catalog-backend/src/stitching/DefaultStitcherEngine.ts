/*
 * Copyright 2023 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { stringifyError } from '@backstage/errors';
import { HumanDuration } from '@backstage/types';
import { Knex } from 'knex';
import { Logger } from 'winston';
import { getStitchableEntities } from '../database/operations/stitcher/getStitchableEntities';
import { startTaskPipeline } from '../processing/TaskPipeline';
import { durationToMs } from '../util/durationToMs';
import { Stitcher, StitcherEngine } from './types';

interface StitchableItem {
  entityRef: string;
  stitchTicket: string;
}

/**
 * Drives the loop that runs deferred stitching of entities.
 */
export class DefaultStitcherEngine implements StitcherEngine {
  private readonly stitcher: Stitcher;
  private readonly database: Knex;
  private readonly logger: Logger;
  private readonly pollingInterval: HumanDuration;
  private readonly stitchTimeout: HumanDuration;
  private stopFunc?: () => void;

  constructor(options: {
    stitcher: Stitcher;
    database: Knex;
    logger: Logger;
    pollingInterval?: HumanDuration;
    stitchTimeout?: HumanDuration;
  }) {
    this.stitcher = options.stitcher;
    this.database = options.database;
    this.logger = options.logger;
    this.pollingInterval = options.pollingInterval ?? { seconds: 1 };
    this.stitchTimeout = options.stitchTimeout ?? { seconds: 60 };
  }

  async start() {
    if (this.stopFunc) {
      throw new Error('Processing engine is already started');
    }

    const stopPipeline = this.startPipeline();

    this.stopFunc = () => {
      stopPipeline();
    };
  }

  async stop() {
    if (this.stopFunc) {
      this.stopFunc();
      this.stopFunc = undefined;
    }
  }

  private startPipeline(): () => void {
    return startTaskPipeline<StitchableItem>({
      lowWatermark: 2,
      highWatermark: 5,
      pollingIntervalMs: durationToMs(this.pollingInterval),
      loadTasks: async count => {
        try {
          return await getStitchableEntities({
            knex: this.database,
            batchSize: count,
            stitchTimeout: this.stitchTimeout,
          });
        } catch (error) {
          this.logger.warn('Failed to load stitching items', error);
          return [];
        }
      },
      processTask: async item => {
        try {
          await this.stitcher.stitchOne(item);
        } catch (error) {
          this.logger.error(
            `Failed to stitch ${item.entityRef}, ${stringifyError(error)}`,
          );
        }
      },
    });
  }
}
