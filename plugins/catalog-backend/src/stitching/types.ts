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

export interface StitcherEngine {
  start(): Promise<void>;
  stop(): Promise<void>;
}

export interface Stitcher {
  markForStitching(options: {
    entityRefs?: Iterable<string>;
    entityIds?: Iterable<string>;
  }): Promise<void>;

  stitchOne(options: {
    entityRef: string;
    stitchTicket?: string;
  }): Promise<void>;
}
