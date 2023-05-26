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
import { metrics } from '@opentelemetry/api';
import { Knex } from 'knex';
import { DateTime } from 'luxon';
import { Logger } from 'winston';
import { getStitchableEntities } from '../database/operations/stitcher/getStitchableEntities';
import { DbRefreshStateRow } from '../database/tables';
import { startTaskPipeline } from '../processing/TaskPipeline';
import { durationToMs } from '../util/durationToMs';
import { createCounterMetric } from '../util/metrics';
import { Stitcher, StitcherEngine } from './types';

type StitchableItem = Awaited<ReturnType<typeof getStitchableEntities>>[0];

export type StitchProgressTracker = ReturnType<typeof progressTracker>;

/**
 * Drives the loop that runs deferred stitching of entities.
 */
export class DefaultStitcherEngine implements StitcherEngine {
  private readonly knex: Knex;
  private readonly stitcher: Stitcher;
  private readonly logger: Logger;
  private readonly pollingInterval: HumanDuration;
  private readonly stitchTimeout: HumanDuration;
  private readonly tracker: StitchProgressTracker;
  private stopFunc?: () => void;

  constructor(options: {
    knex: Knex;
    stitcher: Stitcher;
    logger: Logger;
    pollingInterval?: HumanDuration;
    stitchTimeout?: HumanDuration;
  }) {
    this.stitcher = options.stitcher;
    this.knex = options.knex;
    this.logger = options.logger;
    this.pollingInterval = options.pollingInterval ?? { seconds: 1 };
    this.stitchTimeout = options.stitchTimeout ?? { seconds: 60 };
    this.tracker = progressTracker(options.knex, options.logger);
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
            knex: this.knex,
            batchSize: count,
            stitchTimeout: this.stitchTimeout,
          });
        } catch (error) {
          this.logger.warn('Failed to load stitching items', error);
          return [];
        }
      },
      processTask: async item => {
        const track = this.tracker.stitchStart(item);
        try {
          const result = await this.stitcher.stitchOne(item);
          track.markComplete(result);
        } catch (error) {
          track.markFailed(error);
        }
      },
    });
  }
}

// Helps wrap the timing and logging behaviors
function progressTracker(knex: Knex, logger: Logger) {
  // prom-client metrics are deprecated in favour of OpenTelemetry metrics.
  const promStitchedEntities = createCounterMetric({
    name: 'catalog_stitched_entities_count',
    help: 'Amount of entities stitched. DEPRECATED, use OpenTelemetry metrics instead',
  });

  const meter = metrics.getMeter('default');

  const stitchedEntities = meter.createCounter(
    'catalog.stitched.entities.count',
    {
      description: 'Amount of entities stitched',
    },
  );

  const stitchingDuration = meter.createHistogram(
    'catalog.stitching.duration',
    {
      description: 'Time spent executing the full stitching flow',
      unit: 'seconds',
    },
  );

  const stitchingQueueCount = meter.createObservableGauge(
    'catalog.stitching.queue.length',
    { description: 'Number of entities currently in the stitching queue' },
  );
  stitchingQueueCount.addCallback(async result => {
    const total = await knex<DbRefreshStateRow>('refresh_state')
      .count({ count: '*' })
      .whereNotNull('next_stitch_at');
    result.observe(Number(total[0].count));
  });

  const stitchingQueueDelay = meter.createHistogram(
    'catalog.stitching.queue.delay',
    {
      description:
        'The amount of delay between being scheduled for stitching, and the start of actually being stitched',
      unit: 'seconds',
    },
  );

  function stitchStart(item: { entityRef: string; stitchAt: DateTime }) {
    logger.debug(`Stitching ${item.entityRef}`);

    const startTime = process.hrtime();
    stitchingQueueDelay.record(-item.stitchAt.diffNow().as('seconds'));

    function endTime() {
      const delta = process.hrtime(startTime);
      return delta[0] + delta[1] / 1e9;
    }

    function markComplete(result: string) {
      promStitchedEntities.inc(1);
      stitchedEntities.add(1, { result });
      stitchingDuration.record(endTime(), { result });
    }

    function markFailed(error: Error) {
      promStitchedEntities.inc(1);
      stitchedEntities.add(1, { result: 'error' });
      stitchingDuration.record(endTime(), { result: 'error' });
      logger.error(
        `Failed to stitch ${item.entityRef}, ${stringifyError(error)}`,
      );
    }

    return {
      markComplete,
      markFailed,
    };
  }

  return { stitchStart };
}
