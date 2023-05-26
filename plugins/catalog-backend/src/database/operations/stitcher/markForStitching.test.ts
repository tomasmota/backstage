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

import { TestDatabases } from '@backstage/backend-test-utils';
import { applyDatabaseMigrations } from '../../migrations';
import { markForStitching } from './markForStitching';
import { DbRefreshStateRow } from '../../tables';

jest.setTimeout(60_000);

describe('markForStitching', () => {
  const databases = TestDatabases.create({
    ids: ['MYSQL_8', 'POSTGRES_13', 'POSTGRES_9', 'SQLITE_3'],
  });

  it.each(databases.eachSupportedId())(
    'marks the right rows %p',
    async databaseId => {
      const knex = await databases.init(databaseId);
      await applyDatabaseMigrations(knex);

      await knex<DbRefreshStateRow>('refresh_state').insert([
        {
          entity_id: '1',
          entity_ref: 'k:ns/one',
          unprocessed_entity: '{}',
          processed_entity: '{}',
          errors: '[]',
          next_update_at: knex.fn.now(),
          last_discovery_at: knex.fn.now(),
          next_stitch_at: null,
          next_stitch_ticket: null,
        },
        {
          entity_id: '2',
          entity_ref: 'k:ns/two',
          unprocessed_entity: '{}',
          processed_entity: '{}',
          errors: '[]',
          next_update_at: knex.fn.now(),
          last_discovery_at: knex.fn.now(),
          next_stitch_at: null,
          next_stitch_ticket: null,
        },
        {
          entity_id: '3',
          entity_ref: 'k:ns/three',
          unprocessed_entity: '{}',
          processed_entity: '{}',
          errors: '[]',
          next_update_at: knex.fn.now(),
          last_discovery_at: knex.fn.now(),
          next_stitch_at: null,
          next_stitch_ticket: null,
        },
        {
          entity_id: '4',
          entity_ref: 'k:ns/four',
          unprocessed_entity: '{}',
          processed_entity: '{}',
          errors: '[]',
          next_update_at: knex.fn.now(),
          last_discovery_at: knex.fn.now(),
          next_stitch_at: '1971-01-01T00:00:00.000',
          next_stitch_ticket: 'old',
        },
      ]);

      async function result() {
        return knex<DbRefreshStateRow>('refresh_state')
          .select('entity_id', 'next_stitch_at', 'next_stitch_ticket')
          .orderBy('entity_id', 'asc');
      }

      const original = await result();

      await markForStitching({ entityRefs: new Set(), knex });
      await expect(result()).resolves.toEqual([
        { entity_id: '1', next_stitch_at: null, next_stitch_ticket: null },
        { entity_id: '2', next_stitch_at: null, next_stitch_ticket: null },
        { entity_id: '3', next_stitch_at: null, next_stitch_ticket: null },
        {
          entity_id: '4',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: 'old',
        },
      ]);

      await markForStitching({ entityRefs: new Set(['k:ns/one']), knex });
      await expect(result()).resolves.toEqual([
        {
          entity_id: '1',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: expect.anything(),
        },
        { entity_id: '2', next_stitch_at: null, next_stitch_ticket: null },
        { entity_id: '3', next_stitch_at: null, next_stitch_ticket: null },
        {
          entity_id: '4',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: 'old',
        },
      ]);

      await markForStitching({ entityRefs: ['k:ns/two'], knex });
      await expect(result()).resolves.toEqual([
        {
          entity_id: '1',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: expect.anything(),
        },
        {
          entity_id: '2',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: expect.anything(),
        },
        { entity_id: '3', next_stitch_at: null, next_stitch_ticket: null },
        {
          entity_id: '4',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: 'old',
        },
      ]);

      await markForStitching({ entityIds: ['3', '4'], knex });
      await expect(result()).resolves.toEqual([
        {
          entity_id: '1',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: expect.anything(),
        },
        {
          entity_id: '2',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: expect.anything(),
        },
        {
          entity_id: '3',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: expect.anything(),
        },
        {
          entity_id: '4',
          next_stitch_at: expect.anything(),
          next_stitch_ticket: expect.anything(),
        },
      ]);

      // It overwrites timers and tickets if they existed before
      const final = await result();
      for (let i = 0; i < final.length; ++i) {
        expect(original[i].next_stitch_at).not.toEqual(final[i].next_stitch_at);
        expect(original[i].next_stitch_ticket).not.toEqual(
          final[i].next_stitch_ticket,
        );
      }
    },
  );
});
