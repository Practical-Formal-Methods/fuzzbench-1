# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import random
import os
import tempfile
import multiprocessing
from typing import List

from common import experiment_utils
from common import filesystem
from common import logs

MAX_RANDOM_CORPUS_FILES = 1


def initialize_random_corpus_fuzzing(benchmarks: List[str], num_trials: int):
    """Prepare required assets for random corpus experiment."""
    with multiprocessing.Pool() as pool:
        pool.starmap(prepare_benchmark_random_corpus,
                     [(benchmark, num_trials) for benchmark in benchmarks])


def prepare_benchmark_random_corpus(benchmark: str, num_trials: int):
    """Selects files from custom corpus and ensures that all
    trials in the same group start with the same set of seeds."""
    # path to store and feed seed corpus for benchmark runner
    benchmark_random_corpora = os.path.join(
        experiment_utils.get_random_corpora_filestore_path(), benchmark)
    filesystem.create_directory(benchmark_random_corpora)

    # get inputs from the custom seed corpus directory
    benchmark_custom_corpus_dir = os.path.join(
        experiment_utils.get_custom_seed_corpora_filestore_path(), benchmark)

    with tempfile.TemporaryDirectory() as tmp_dir:
        all_corpus_files = []
        for root, _, files in os.walk(benchmark_custom_corpus_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                all_corpus_files.append(file_path)

        # all trials in the same group will start with the same
        # set of randomly selected seed files
        for trial_group_num in range(num_trials):
            logs.info('Preparing random corpus: %s, trial_group: %d', benchmark,
                      trial_group_num)

            trial_group_subdir = 'trial-group-%d' % trial_group_num
            custom_corpus_trial_dir = os.path.join(benchmark_random_corpora,
                                                   trial_group_subdir)

            src_dir = os.path.join(tmp_dir, "source")
            filesystem.recreate_directory(src_dir)

            # random selection of custom seeds
            selected_files = random.sample(all_corpus_files,
                                           MAX_RANDOM_CORPUS_FILES)
            for file in selected_files:
                filesystem.copy(file, src_dir)

            # copy the src directory
            filesystem.copytree(src_dir, custom_corpus_trial_dir)
