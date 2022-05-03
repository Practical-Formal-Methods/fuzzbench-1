import random
import os
import zipfile
import tempfile
import tarfile
import multiprocessing
import itertools
from typing import List

from common import experiment_utils
from common import filesystem
from experiment.measurer import coverage_utils
from experiment.measurer import run_coverage
from database import utils as db_utils
from database import models
from common import logs
from common import benchmark_utils
from experiment.build import build_utils
from common import experiment_path as exp_path

MAX_CORPUS_FILES = 5


def get_covered_branches_per_function(coverage_info):
    function_coverage_info = coverage_info["data"][0]["functions"]
    covered_branches = set([])
    for function in function_coverage_info:
        function_name = function["name"]
        for branch in function["branches"]:
            if branch[4]:
                coverage_key = "{} {}:{}-{}:{} T".format(
                    function_name, branch[0], branch[1], branch[2], branch[3])
                covered_branches.add(coverage_key)
            if branch[5]:
                coverage_key = "{} {}:{}-{}:{} F".format(
                    function_name, branch[0], branch[1], branch[2], branch[3])
                covered_branches.add(coverage_key)
    return covered_branches


def get_covered_branches(coverage_binary, corpus_dir):
    with tempfile.TemporaryDirectory() as tmp_dir:
        profdata_file = os.path.join(tmp_dir, 'data.profdata')
        merged_profdata_file = os.path.join(tmp_dir, 'merged.profdata')
        merged_summary_json_file = os.path.join(tmp_dir, 'merged.json')
        crashes_dir = os.path.join(tmp_dir, 'crashes')
        filesystem.create_directory(crashes_dir)

        run_coverage.do_coverage_run(coverage_binary, corpus_dir, profdata_file,
                                     crashes_dir)
        coverage_utils.merge_profdata_files([profdata_file],
                                            merged_profdata_file)
        coverage_utils.generate_json_summary(coverage_binary,
                                             merged_profdata_file,
                                             merged_summary_json_file,
                                             summary_only=False)
        coverage_info = coverage_utils.get_coverage_infomation(
            merged_summary_json_file)
        return get_covered_branches_per_function(coverage_info)


def main_loop(benchmarks: List[str], num_trials: int):
    pool_args = ()
    with multiprocessing.Pool(*pool_args) as pool:
        target_coverage_list = pool.starmap(
            setup_fuzzing_target,
            [(benchmark, num_trials) for benchmark in benchmarks])
        target_coverage = list(itertools.chain(*target_coverage_list))
        logs.info('Done Preparing target fuzzing (total %d target)',
                  len(target_coverage))
        db_utils.bulk_save(target_coverage)


def setup_fuzzing_target(benchmark: str, num_trials: int):
    with tempfile.TemporaryDirectory() as tmp_dir:
        coverage_binaries_dir = build_utils.get_coverage_binaries_dir()
        archive_name = 'coverage-build-%s.tar.gz' % benchmark
        archive_filestore_path = exp_path.filestore(coverage_binaries_dir /
                                                    archive_name)
        filesystem.copy(archive_filestore_path, tmp_dir)
        archive_path = os.path.join(tmp_dir, archive_name)
        tar = tarfile.open(archive_path, 'r:gz')
        tar.extractall(tmp_dir)
        os.remove(archive_path)
        coverage_binary = os.path.join(
            tmp_dir, benchmark_utils.get_fuzz_target(benchmark))
        return prepare_target_fuzzing_corpus(benchmark, num_trials,
                                             coverage_binary)


def prepare_target_fuzzing_corpus(benchmark: str, num_trials: int,
                                  coverage_binary: str):
    """Prepare corpus for target fuzzing."""

    target_coverage = []

    # path used to store and feed seed corpus for benchmark runner
    # each trial group will have the same seed input(s)
    target_fuzzing_benchmark = os.path.join(
        experiment_utils.get_target_fuzzing_corpora_filestore_path(), benchmark)
    filesystem.create_directory(target_fuzzing_benchmark)

    # randomly pick from custom seed corpus
    corpus_archive_filename = os.path.join(
        experiment_utils.get_custom_seed_corpora_filestore_path(),
        f'{benchmark}.zip')
    with tempfile.TemporaryDirectory() as tmp_dir:
        with zipfile.ZipFile(corpus_archive_filename) as zip_file:
            # only consider file not directory
            corpus_files = [
                f for f in zip_file.infolist() if not f.filename.endswith('/')
            ]
            for trial_group_num in range(num_trials):
                logs.info('Preparing target fuzzing: %s, trial_group: %d',
                          benchmark, trial_group_num)

                trial_group_subdir = 'trial-group-%d' % trial_group_num
                target_fuzzing_trial_dir = os.path.join(
                    target_fuzzing_benchmark, trial_group_subdir)
                src_dir = os.path.join(tmp_dir, "source")
                dest_dir = os.path.join(tmp_dir, "dest")
                filesystem.recreate_directory(src_dir)
                filesystem.recreate_directory(dest_dir)

                source_files = random.sample(corpus_files, MAX_CORPUS_FILES)
                for file in source_files:
                    zip_file.extract(file, src_dir)

                dest_files = random.sample(corpus_files, MAX_CORPUS_FILES)
                for file in dest_files:
                    zip_file.extract(file, dest_dir)

                src_branches = get_covered_branches(coverage_binary, src_dir)
                dest_branches = get_covered_branches(coverage_binary, dest_dir)
                target_branches = dest_branches - src_branches

                if not target_branches:
                    raise RuntimeError(
                        'Unable to find target branches for %s.' % benchmark)

                for branch in target_branches:
                    target_cov = models.TargetCoverage()
                    target_cov.trial_group_num = int(trial_group_num)
                    target_cov.benchmark = benchmark
                    target_cov.target_location = branch
                    target_coverage.append(target_cov)

                # copy only the src directory
                filesystem.copytree(src_dir, target_fuzzing_trial_dir)

    return target_coverage
