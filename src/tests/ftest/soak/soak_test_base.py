#!/usr/bin/python
"""
(C) Copyright 2019-2021 Intel Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import os
import time
from datetime import datetime, timedelta
import multiprocessing
import threading
import random
from filecmp import cmp
from apricot import TestWithServers
from general_utils import run_command, DaosTestError, get_log_file
from command_utils_base import CommandFailure
import slurm_utils
from ClusterShell.NodeSet import NodeSet
from getpass import getuser
import socket
from agent_utils import include_local_host
from soak_utils import DDHHMMSS_format, add_pools, get_remote_logs, \
    launch_snapshot, launch_exclude_reintegrate, \
    create_ior_cmdline, cleanup_dfuse, create_fio_cmdline, \
    build_job_script, SoakTestError, launch_server_stop_start, get_harassers, \
    create_racer_cmdline, run_event_check, run_monitor_check, \
    create_mdtest_cmdline, reserved_file_copy, cleanup_dfuse


class SoakTestBase(TestWithServers):
    # pylint: disable=too-many-public-methods
    # pylint: disable=too-many-instance-attributes
    """Execute DAOS Soak test cases.

    :avocado: recursive
    """

    def __init__(self, *args, **kwargs):
        """Initialize a SoakBase object."""
        super().__init__(*args, **kwargs)
        self.failed_job_id_list = None
        self.test_log_dir = None
        self.exclude_slurm_nodes = None
        self.loop = None
        self.log_dir = None
        self.outputsoakdir = None
        self.test_name = None
        self.test_timeout = None
        self.end_time = None
        self.soak_results = None
        self.srun_params = None
        self.harassers = None
        self.offline_harassers = None
        self.harasser_results = None
        self.all_failed_jobs = None
        self.username = None
        self.used = None
        self.dfuse = []
        self.harasser_args = None
        self.harasser_loop_time = None
        self.all_failed_harassers = None
        self.soak_errors = None
        self.check_errors = None

    def setUp(self):
        """Define test setup to be done."""
        self.log.info("<<setUp Started>> at %s", time.ctime())
        super().setUp()
        self.username = getuser()
        # Initialize loop param for all tests
        self.loop = 1
        self.exclude_slurm_nodes = []
        # Setup logging directories for soak logfiles
        # self.output dir is an avocado directory .../data/
        self.log_dir = get_log_file("soak")
        self.outputsoakdir = self.outputdir + "/soak"
        # Create the remote log directories on all client nodes
        self.test_log_dir = self.log_dir + "/pass" + str(self.loop)
        self.local_pass_dir = self.outputsoakdir + "/pass" + str(self.loop)
        self.sharedlog_dir = self.tmp + "/soak"
        self.sharedsoakdir = self.sharedlog_dir + "/pass" + str(self.loop)
        # Initialize dmg cmd
        self.dmg_command = self.get_dmg_command()
        # Fail if slurm partition is not defined
        # NOTE: Slurm reservation and partition are created before soak runs.
        # CI uses partition=daos_client and no reservation.
        # A21 uses partition=normal/default and reservation=daos-test.
        # Partition and reservation names are updated in the yaml file.
        # It is assumed that if there is no reservation (CI only), then all
        # the nodes in the partition will be used for soak.
        if not self.client_partition:
            raise SoakTestError(
                "<<FAILED: Partition is not correctly setup for daos "
                "slurm partition>>")
        self.srun_params = {"partition": self.client_partition}
        if self.client_reservation:
            self.srun_params["reservation"] = self.client_reservation
        # Check if the server nodes are in the client list;
        # this will happen when only one partition is specified
        for host_server in self.hostlist_servers:
            if host_server in self.hostlist_clients:
                self.hostlist_clients.remove(host_server)
                self.exclude_slurm_nodes.append(host_server)
        # Include test node for log cleanup; remove from client list
        local_host_list = include_local_host(None)
        self.exclude_slurm_nodes.extend(local_host_list)
        if local_host_list[0] in self.hostlist_clients:
            self.hostlist_clients.remove((local_host_list[0]))
        if not self.hostlist_clients:
            self.fail(
                "There are no valid nodes in this partition to run "
                "soak. Check partition {} for valid nodes".format(
                    self.client_partition))

    def pre_tear_down(self):
        """Tear down any test-specific steps prior to running tearDown().

        Returns:
            list: a list of error strings to report after all tear down
            steps have been attempted

        """
        self.log.info("<<preTearDown Started>> at %s", time.ctime())
        errors = []
        # clear out any jobs in squeue;
        if self.failed_job_id_list:
            job_id = " ".join([str(job) for job in self.failed_job_id_list])
            self.log.info("<<Cancel jobs in queue with ids %s >>", job_id)
            try:
                run_command(
                    "scancel --partition {} -u {} {}".format(
                        self.client_partition, self.username, job_id))
            except DaosTestError as error:
                # Exception was raised due to a non-zero exit status
                errors.append("Failed to cancel jobs {}: {}".format(
                    self.failed_job_id_list, error))
        if self.all_failed_jobs:
            errors.append("SOAK FAILED: The following jobs failed {} ".format(
                " ,".join(str(j_id) for j_id in self.all_failed_jobs)))
        if self.all_failed_harassers:
            errors.extend(self.all_failed_harassers)
        if self.soak_errors:
            errors.extend(self.soak_errors)
        if self.check_errors:
            errors.extend(self.check_errors)
        # Check if any dfuse mount points need to be cleaned
        cleanup_dfuse(self)
        # daos_agent is always started on this node when start agent is false
        if not self.setup_start_agents:
            self.hostlist_clients = [socket.gethostname().split('.', 1)[0]]
        for error in errors:
            self.log.info("<<ERRORS: %s >>\n", error)
        return errors

    def launch_harasser(self, harasser, pool):
        """Launch any harasser tests if defined in yaml.

        Args:
            harasser (str): harasser to launch
            pool (list): list of TestPool obj

        Returns:
            status_msg(str): pass/fail status message

        """
        # Init the status message
        status_msg = None
        job = None
        results = multiprocessing.Queue()
        args = multiprocessing.Queue()
        # Launch harasser
        self.log.info("\n<<<Launch harasser %s>>>\n", harasser)
        if harasser == "snapshot":
            method = launch_snapshot
            name = "SNAPSHOT"
            params = (self, self.pool[0], name)
            job = threading.Thread(target=method, args=params, name=name)
        elif harasser == "exclude":
            method = launch_exclude_reintegrate
            name = "EXCLUDE"
            params = (self, pool[1], name, results, args)
            job = multiprocessing.Process(target=method, args=params, name=name)
        elif harasser == "reintegrate":
            method = launch_exclude_reintegrate
            name = "REINTEGRATE"
            params = (self, pool[1], name, results, args)
            job = multiprocessing.Process(target=method, args=params, name=name)
        elif harasser == "server-stop":
            method = launch_server_stop_start
            name = "SVR_STOP"
            params = (self, pool, name, results, args)
            job = multiprocessing.Process(target=method, args=params, name=name)
        elif harasser == "server-start":
            method = launch_server_stop_start
            name = "SVR_START"
            params = (self, pool, name, results, args)
            job = multiprocessing.Process(target=method, args=params, name=name)
        elif harasser == "server-reintegrate":
            method = launch_server_stop_start
            name = "SVR_REINTEGRATE"
            params = (self, pool, name, results, args)
            job = multiprocessing.Process(target=method, args=params, name=name)
        else:
            raise SoakTestError(
                "<<FAILED: Harasser {} is not supported. ".format(
                    harasser))

        # start harasser
        job.start()
        timeout = self.params.get("harasser_to", "/run/soak_harassers/*", 30)
        # Wait for harasser job to join
        job.join(timeout)
        if job.is_alive():
            self.log.error(
                "<< ERROR: harasser %s is alive, failed to join>>", job.name)
            if name not in ["REBUILD", "SNAPSHOT"]:
                job.terminate()
                status_msg = "<<FAILED: {} has been terminated.".format(name)
            raise SoakTestError(
                "<<FAILED: Soak failed while running {} . ".format(name))
        if name not in ["REBUILD", "SNAPSHOT"]:
            self.harasser_results = results.get()
            self.harasser_args = args.get()
        # Check if the completed job passed
        self.log.info("Harasser results: %s", self.harasser_results)
        self.log.info("Harasser args: %s", self.harasser_args)
        if not self.harasser_results[name.upper()]:
            status_msg = "<< HARASSER {} FAILED in pass {} at {}>> ".format(
                name, self.loop, time.ctime())
            self.log.error(status_msg)
        return status_msg

    def harasser_job_done(self, args):
        """Call this function when a job is done.

        Args:
            args (list):name   job name of harasser,
                        status  job completion status
                        vars:   variables used in harasser
        """
        self.harasser_results[args["name"]] = args["status"]
        self.harasser_args[args["name"]] = args["vars"]

    def job_setup(self, jobs, pool):
        """Create the cmdline needed to launch job.

        Args:
            jobs(list): list of jobs to run
            pool (obj): TestPool obj

        Returns:
            job_cmdlist: list of sbatch scripts that can be launched
                         by slurm job manager

        """
        job_cmdlist = []
        self.log.info("<<Job_Setup %s >> at %s", self.test_name, time.ctime())
        for job in jobs:
            jobscript = []
            commands = []
            nodesperjob = self.params.get(
                "nodesperjob", "/run/" + job + "/*", [1])
            taskspernode = self.params.get(
                "taskspernode", "/run/" + job + "/*", [1])
            for npj in list(nodesperjob):
                # nodesperjob = -1 indicates to use all nodes in client hostlist
                if npj < 0:
                    npj = len(self.hostlist_clients)
                if len(self.hostlist_clients)/npj < 1:
                    raise SoakTestError(
                        "<<FAILED: There are only {} client nodes for this job."
                        " Job requires {}".format(
                            len(self.hostlist_clients), npj))
                for ppn in list(taskspernode):
                    if "ior" in job:
                        commands = create_ior_cmdline(self, job, pool, ppn, npj)
                    elif "fio" in job:
                        commands = create_fio_cmdline(self, job, pool)
                    elif "mdtest" in job:
                        commands = create_mdtest_cmdline(
                            self, job, pool, ppn, npj)
                    elif "daos_racer" in job:
                        self.add_cancel_ticket(
                            "DAOS-7436", "daos_racer pool issue")
                        # Uncomment the following when DAOS-7436 is fixed
                        # commands = create_racer_cmdline(self, job, pool)
                    else:
                        raise SoakTestError(
                            "<<FAILED: Job {} is not supported. ".format(
                                self.job))
                    jobscript = build_job_script(self, commands, job, npj)
                    job_cmdlist.extend(jobscript)
        return job_cmdlist

    def job_startup(self, job_cmdlist):
        """Submit job batch script.

        Args:
            job_cmdlist (list): list of jobs to execute
        Returns:
            job_id_list: IDs of each job submitted to slurm.

        """
        self.log.info(
            "<<Job Startup - %s >> at %s", self.test_name, time.ctime())
        job_id_list = []
        # before submitting the jobs to the queue, check the job timeout;
        if time.time() > self.end_time:
            self.log.info("<< SOAK test timeout in Job Startup>>")
            return job_id_list
        # job_cmdlist is a list of batch script files

        for script in job_cmdlist:
            try:
                job_id = slurm_utils.run_slurm_script(str(script))
            except slurm_utils.SlurmFailed as error:
                self.log.error(error)
                # Force the test to exit with failure
                job_id = None
            if job_id:
                self.log.info(
                    "<<Job %s started with %s >> at %s",
                    job_id, script, time.ctime())
                slurm_utils.register_for_job_results(
                    job_id, self, maxwait=self.test_timeout)
                # keep a list of the job_id's
                job_id_list.append(int(job_id))
            else:
                # one of the jobs failed to queue; exit on first fail for now.
                err_msg = "Slurm failed to submit job for {}".format(script)
                job_id_list = []
                raise SoakTestError(
                    "<<FAILED:  Soak {}: {}>>".format(self.test_name, err_msg))
        return job_id_list

    def job_completion(self, job_id_list):
        """Wait for job completion and cleanup.

        Args:
            job_id_list: IDs of each job submitted to slurm
        Returns:
            failed_job_id_list: IDs of each job that failed in slurm

        """
        self.log.info(
            "<<Job Completion - %s >> at %s", self.test_name, time.ctime())
        harasser_interval = 0
        failed_harasser_msg = None
        harasser_timer = time.time()
        check_time = datetime.now()
        event_check_messages = []
        since = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # loop time exists after the first pass; no harassers in the first pass
        if self.harasser_loop_time and self.harassers:
            harasser_interval = self.harasser_loop_time / (
                len(self.harassers) + 1)
        # If there is nothing to do; exit
        if job_id_list:
            # wait for all the jobs to finish
            while len(self.soak_results) < len(job_id_list):
                # wait for the jobs to complete.
                # enter tearDown before hitting the avocado timeout
                if time.time() > self.end_time:
                    self.log.info(
                        "<< SOAK test timeout in Job Completion at %s >>",
                        time.ctime())
                    for job in job_id_list:
                        _ = slurm_utils.cancel_jobs(int(job))
                # monitor events every 15 min
                if datetime.now() > check_time:
                    run_monitor_check(self)
                    check_time = datetime.now() + timedelta(minutes=15)
                # launch harassers if enabled;
                # one harasser at a time starting on pass2
                if self.harassers:
                    if self.loop >= 2 and (
                            time.time() > (harasser_timer + harasser_interval)):
                        harasser = self.harassers.pop(0)
                        harasser_timer += harasser_interval
                        failed_harasser_msg = self.launch_harasser(
                            harasser, self.pool)
                time.sleep(5)
            if time.time() < self.end_time:
                # Run any offline harassers after first loop
                if self.offline_harassers and self.loop >= 1:
                    for offline_harasser in self.offline_harassers:
                        if time.time() + int(180) < self.end_time:
                            failed_harasser_msg = self.launch_harasser(
                                offline_harasser, self.pool)
                            # wait 2 minutes to issue next harasser
                            time.sleep(120)
            # check journalctl for events;
            until = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            event_check_messages = run_event_check(self, since, until)
            self.check_errors.extend(event_check_messages)
            run_monitor_check(self)
            # init harasser list when all jobs are done
            self.harassers = []
            self.offline_harassers = []
            if failed_harasser_msg is not None:
                self.all_failed_harassers.append(failed_harasser_msg)
            # check for JobStatus = COMPLETED or CANCELLED (i.e. TEST TO)
            for job, result in list(self.soak_results.items()):
                if result in ["COMPLETED", "CANCELLED"]:
                    job_id_list.remove(int(job))
                else:
                    self.log.info(
                        "<< Job %s failed with status %s>>", job, result)
            # gather all the logfiles for this pass and cleanup test nodes
            try:
                get_remote_logs(self)
            except SoakTestError as error:
                self.log.info("Remote copy failed with %s", error)
            self.soak_results = {}
        return job_id_list

    def job_done(self, args):
        """Call this function when a job is done.

        Args:
            args (list):handle --which job, i.e. the job ID,
                        state  --string indicating job completion status
        """
        self.soak_results[args["handle"]] = args["state"]

    def execute_jobs(self, jobs, pools):
        """Execute the overall soak test.

        Args:
            pools (list): list of TestPool obj - self.pool[1:]

        Raise:
            SoakTestError

        """
        job_script_list = []
        # Update the remote log directories from new loop/pass
        self.sharedsoakdir = self.sharedlog_dir + "/pass" + str(self.loop)
        self.test_log_dir = self.log_dir + "/pass" + str(self.loop)
        local_pass_dir = self.outputsoakdir + "/pass" + str(self.loop)
        result = slurm_utils.srun(
            NodeSet.fromlist(self.hostlist_clients), "mkdir -p {}".format(
                self.test_log_dir), self.srun_params)
        if result.exit_status > 0:
            raise SoakTestError(
                "<<FAILED: logfile directory not"
                "created on clients>>: {}".format(self.hostlist_clients))
        # Create local log directory
        os.makedirs(local_pass_dir)
        os.makedirs(self.sharedsoakdir)
        # create the batch scripts
        job_script_list = self.job_setup(jobs, pools)
        # randomize job list
        random.seed(4)
        random.shuffle(job_script_list)
        # Gather the job_ids
        job_id_list = self.job_startup(job_script_list)
        # Initialize the failed_job_list to job_list so that any
        # unexpected failures will clear the squeue in tearDown
        self.failed_job_id_list = job_id_list

        # Wait for jobs to finish and cancel/kill jobs if necessary
        self.failed_job_id_list = self.job_completion(job_id_list)
        # Log the failing job ID
        if self.failed_job_id_list:
            self.log.info(
                "<<FAILED: The following jobs failed %s >>", (" ,".join(
                    str(j_id) for j_id in self.failed_job_id_list)))
            # accumulate failing job IDs
            self.all_failed_jobs.extend(self.failed_job_id_list)
            # clear out the failed jobs for this pass
            self.failed_job_id_list = []

    def run_soak(self, test_param):
        """Run the soak test specified by the test params.

        Args:
            test_param (str): test_params from yaml file

        """
        self.soak_results = {}
        self.pool = []
        self.container = []
        self.harasser_results = {}
        self.harasser_args = {}
        run_harasser = False
        self.all_failed_jobs = []
        self.all_failed_harassers = []
        self.soak_errors = []
        self.check_errors = []
        self.used = []
        test_to = self.params.get("test_timeout", test_param + "*")
        self.test_name = self.params.get("name", test_param + "*")
        single_test_pool = self.params.get(
            "single_test_pool", test_param + "*", True)
        harassers = self.params.get("harasserlist", test_param + "*")
        job_list = self.params.get("joblist", test_param + "*")
        if harassers:
            run_harasser = True
            self.log.info("<< Initial harasser list = %s>>", harassers)
            harasserlist = harassers[:]
        # Create the reserved pool with data
        # self.pool is a list of all the pools used in soak
        # self.pool[0] will always be the reserved pool
        add_pools(self, ["pool_reserved"])
        # Create the reserved container
        resv_cont = self.get_container(
            self.pool[0], "/run/container_reserved/*", True)
        # populate reserved container with a 500MB file
        initial_resv_file = os.path.join(
            os.environ["DAOS_TEST_LOG_DIR"], "initial", "resv_file")
        try:
            reserved_file_copy(self, initial_resv_file, self.pool[0], resv_cont,
                               num_bytes=500000000, cmd="write")
        except CommandFailure as error:
            self.fail(error)

        # Create pool for jobs
        if single_test_pool:
            add_pools(self, ["pool_jobs"])
            self.log.info(
                "Current pools: %s",
                " ".join([pool.uuid for pool in self.pool]))

        # cleanup soak log directories before test on all nodes
        result = slurm_utils.srun(
            NodeSet.fromlist(self.hostlist_clients), "rm -rf {}".format(
                self.log_dir), self.srun_params)
        if result.exit_status > 0:
            raise SoakTestError(
                "<<FAILED: Soak directories not removed"
                "from clients>>: {}".format(self.hostlist_clients))
        # cleanup test_node
        for log_dir in [self.log_dir, self.sharedlog_dir]:
            cmd = "rm -rf {}".format(log_dir)
            try:
                result = run_command(cmd, timeout=30)
            except DaosTestError as error:
                raise SoakTestError(
                    "<<FAILED: Soak directory {} was not removed>>".format(
                        log_dir)) from error

        # Initialize time
        start_time = time.time()
        self.test_timeout = int(3600 * test_to)
        self.end_time = start_time + self.test_timeout
        self.log.info("<<START %s >> at %s", self.test_name, time.ctime())
        while time.time() < self.end_time:
            # Start new pass
            start_loop_time = time.time()
            self.log.info(
                "<<SOAK LOOP %s: time until done %s>>", self.loop,
                DDHHMMSS_format(self.end_time - time.time()))
            if not single_test_pool:
                # Create pool for jobs
                add_pools(self, ["pool_jobs"])
                self.log.info(
                    "Current pools: %s",
                    " ".join([pool.uuid for pool in self.pool]))
            # Initialize harassers
            if run_harasser:
                if not harasserlist:
                    harasserlist = harassers[:]
                harasser = harasserlist.pop(0)
                self.harasser_args = {}
                self.harasser_results = {}
                self.harassers, self.offline_harassers = get_harassers(harasser)
            try:
                self.execute_jobs(job_list, self.pool[1])
            except SoakTestError as error:
                self.fail(error)
            # Check space after jobs done
            for pool in self.pool:
                self.dmg_command.pool_query(pool.uuid)
            # Cleanup any dfuse mounts before destroying containers
            cleanup_dfuse(self)
            self.soak_errors.extend(self.destroy_containers(self.container))
            self.container = []
            # Remove the test pools from self.pool; preserving reserved pool
            if not single_test_pool:
                self.soak_errors.extend(self.destroy_pools(self.pool[1]))
                self.pool = [self.pool[0]]
            self.log.info(
                "Current pools: %s",
                " ".join([pool.uuid for pool in self.pool]))
            # Fail if the pool/containers did not clean up correctly
            self.assertEqual(
                len(self.soak_errors), 0, "\n".join(self.soak_errors))
            # Break out of loop if smoke
            if "smoke" in self.test_name:
                break
            loop_time = time.time() - start_loop_time
            self.log.info(
                "<<LOOP %s completed in %s at %s>>", self.loop, DDHHMMSS_format(
                    loop_time), time.ctime())
            # Initialize harasser loop time from first pass loop time
            if self.loop == 1 and run_harasser:
                self.harasser_loop_time = loop_time
            self.loop += 1
        # verify reserved container data
        final_resv_file = os.path.join(
            os.environ["DAOS_TEST_LOG_DIR"], "final", "resv_file")
        try:
            reserved_file_copy(self, final_resv_file, self.pool[0], resv_cont)
        except CommandFailure as error:
            self.soak_errors.append(
                "<<FAILED: Soak reserved container read failed>>")

        if not cmp(initial_resv_file, final_resv_file):
            self.soak_errors.append("Data verification error on reserved pool"
                                    " after SOAK completed")
        for file in [initial_resv_file, final_resv_file]:
            if os.path.isfile(file):
                file_name = os.path.split(os.path.dirname(file))[-1]
                # save a copy of the POSIX file in self.outputsoakdir
                copy_cmd = "cp -p {} {}/{}_resv_file".format(
                    file, self.outputsoakdir, file_name)
                try:
                    run_command(copy_cmd, timeout=30)
                except DaosTestError as error:
                    self.soak_errors.append(
                        "Reserved data file {} failed to archive".format(file))
                os.remove(file)
        self.container.append(resv_cont)
        # Gather the daos logs from the client nodes
        self.log.info(
            "<<<<SOAK TOTAL TEST TIME = %s>>>>", DDHHMMSS_format(
                time.time() - start_time))
