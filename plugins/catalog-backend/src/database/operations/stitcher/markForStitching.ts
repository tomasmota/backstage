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

import { v4 as uuid } from 'uuid';
import splitToChunks from 'lodash/chunk';
import { Knex } from 'knex';
import { DbRefreshStateRow } from '../../tables';

const BATCH_SIZE = 100;

/**
 * Marks a number of entities for deferred stitching some time in the near
 * future.
 */
export async function markForStitching(options: {
  knex: Knex | Knex.Transaction;
  entityRefs?: Iterable<string>;
  entityIds?: Iterable<string>;
}): Promise<void> {
  const { entityRefs, entityIds, knex } = options;

  // It's OK that this is shared across refresh state rows; it just needs to
  // be uniquely generated for every new stitch request.
  const ticket = uuid();

  if (entityRefs) {
    const chunks = splitToChunks(
      Array.isArray(entityRefs) ? entityRefs : [...entityRefs],
      BATCH_SIZE,
    );

    for (const chunk of chunks) {
      await knex<DbRefreshStateRow>('refresh_state')
        .update({
          next_stitch_at: knex.fn.now(),
          next_stitch_ticket: ticket,
        })
        .whereIn('entity_ref', chunk);
    }
  }

  if (entityIds) {
    const chunks = splitToChunks(
      Array.isArray(entityIds) ? entityIds : [...entityIds],
      BATCH_SIZE,
    );

    for (const chunk of chunks) {
      await knex<DbRefreshStateRow>('refresh_state')
        .update({
          next_stitch_at: knex.fn.now(),
          next_stitch_ticket: ticket,
        })
        .whereIn('entity_id', chunk);
    }
  }
}
