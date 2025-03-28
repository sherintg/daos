#!/usr/bin/python3
"""
  (C) Copyright 2018-2021 Intel Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent
"""
import string

from apricot import TestWithServers, skipForTicket
from avocado.core.exceptions import TestFail
from general_utils import report_errors, get_random_string
from command_utils_base import CommandFailure


class Label(TestWithServers):
    """Test create and destroy a pool with a label.

    :avocado: recursive
    """

    def verify_destroy(self, pool, failure_expected, use_dmg=False):
        """Verify pool destroy works/not work as expected.

        Args:
            pool (TestPool): Pool to destroy.
            failure_expected (bool): Whether failure is expected from pool
                destroy.
            use_dmg (bool): Whether to use dmg object. Defaults to False.

        Returns:
            list: List of errors.

        """
        errors = []

        try:
            if use_dmg:
                pool.dmg.pool_destroy(pool=pool.label.value, force=1)
            else:
                pool.destroy()
            if failure_expected:
                error_message = "dmg pool destroy is expected to fail, " +\
                    "but worked!"
                errors.append(error_message)
        except (TestFail, CommandFailure):
            if not failure_expected:
                error_message = "dmg pool destroy failed! "
                self.log.info(error_message)
                errors.append(error_message)

        return errors

    def verify_create(self, label, failure_expected, expected_error=None):
        """Verify pool create with given label works/not work as expected.

        Args:
            label (str): Label.
            failure_expected (bool): Whether failure is expected from pool
                create.
            expected_error (str): Expected error message. Defaults to None.

        Returns:
            list: List of errors.

        """
        errors = []

        self.pool.append(self.get_pool(create=False))
        self.pool[-1].label.update(label)

        try:
            self.pool[-1].dmg.exit_status_exception = False
            self.pool[-1].create()
            result_stdout = str(self.pool[-1].dmg.result.stdout)
            exit_status = self.pool[-1].dmg.result.exit_status

            if  exit_status == 0 and failure_expected:
                error_message = "dmg pool create is expected to fail, " +\
                    "but worked! {}".format(label)
                errors.append(error_message)
            elif exit_status != 0 and not failure_expected:
                error_message = "dmg pool create failed unexpectedly! " +\
                    "{}".format(label)
                errors.append(error_message)
            elif (exit_status != 0
                  and failure_expected
                  and expected_error not in result_stdout):
                # Failed for the wrong reason.
                error_message = "dmg pool create failed for the wrong " +\
                    "reason! Expected to exist = {}".format(expected_error)
                errors.append(error_message)

        except TestFail as error:
            errors.append(error)
            self.log.info("dmg failed!")

        finally:
            self.pool[-1].dmg.exit_status_exception = True

        return errors

    @skipForTicket("DAOS-8183")
    def test_valid_labels(self):
        """Test ID: DAOS-7942

        Test Description: Create and destroy pool with the following labels.
        * Random alpha numeric string of length 126.
        * Random alpha numeric string of length 127.
        * Random alpha numeric string of length 128.
        * Random upper case string of length 50.
        * Random lower case string of length 50.
        * Random number string of length 50.

        :avocado: tags=all,full_regression
        :avocado: tags=small
        :avocado: tags=pool,create_valid_labels
        """
        self.pool = []
        errors = []
        labels = [
            get_random_string(126),
            get_random_string(127),
            get_random_string(128),
            get_random_string(length=50, include=string.ascii_uppercase),
            get_random_string(length=50, include=string.ascii_lowercase),
            get_random_string(length=50, include=string.digits)
        ]

        for label in labels:
            errors.extend(self.verify_create(label, False))
            errors.extend(self.verify_destroy(self.pool[-1], False))

        report_errors(self, errors)

    def test_invalid_labels(self):
        """Test ID: DAOS-7942

        Test Description: Create pool with following invalid labels.
        * UUID format string: 23ab123e-5296-4f95-be14-641de40b4d5a
        * Long label - 129 random chars.

        :avocado: tags=all,full_regression
        :avocado: tags=small
        :avocado: tags=pool,create_invalid_labels
        """
        self.pool = []
        errors = []
        label_outs = [
            ("23ab123e-5296-4f95-be14-641de40b4d5a", "invalid label"),
            (get_random_string(129), "value too long")
        ]

        for label_out in label_outs:
            errors.extend(self.verify_create(label_out[0], True, label_out[1]))

        report_errors(self, errors)

    def test_duplicate_create(self):
        """Test ID: DAOS-7942

        Test Description:
        1. Create a pool with a label.
        2. Create another pool with the same label. Should fail.
        3. Destroy the pool.
        4. Create a pool with the same label again. It should work this time.

        :avocado: tags=all,full_regression
        :avocado: tags=small
        :avocado: tags=pool,duplicate_label_create
        """
        self.pool = []
        label = "TestLabel"

        # Step 1
        report_errors(self, self.verify_create(label, False))

        # Step 2
        report_errors(self, self.verify_create(label, True, "already exists"))

        # Step 3
        report_errors(self, self.verify_destroy(self.pool[0], False))

        # Step 4
        report_errors(self, self.verify_create(label, False))

    def test_duplicate_destroy(self):
        """Test ID: DAOS-7942

        Test Description:
        1. Create a pool with a label.
        2. Destroy it with the label.
        3. Destroy it with the label again. The second destroy should fail.

        :avocado: tags=all,full_regression
        :avocado: tags=small
        :avocado: tags=pool,duplicate_label_destroy
        """
        self.pool = []

        # Step 1
        report_errors(self, self.verify_create("TestLabel", False))

        # Step 2
        report_errors(self, self.verify_destroy(self.pool[-1], False))

        # Step 3
        report_errors(self, self.verify_destroy(self.pool[-1], True, True))
