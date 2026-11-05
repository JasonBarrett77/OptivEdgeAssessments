"""What a remediation row's cell says when it folds several definitions of one object.

A device-group rule pushed to seven enforcement points is ONE row - one edit on Panorama - and
its cells are read from all seven. Until 2026-11-05 a cell whose seven readings disagreed said
`(differs)` and nothing else, and four such cells on the lab carried the value-at-fault fill:
amber saying "this is the value to change" over a word that is not a value. Jason: *"The differs
should carry all the values. On the values that differ, perhaps just a simple count of how many
appliances carry the differing value."*
"""

from __future__ import annotations

from django.test import SimpleTestCase

from assessments.remediation import NO_VALUE, _agreed_lines


class AgreedLinesTests(SimpleTestCase):
    def test_agreement_is_the_value_alone(self):
        """No annotation where there is nothing to count - which is all but two rows of the
        1,083 on the lab's security-rule page, and every row of a page that folds one object."""
        self.assertEqual(_agreed_lines(["Yes", "Yes", "Yes"], False), ["Yes"])

    def test_nothing_read_is_no_lines(self):
        self.assertEqual(_agreed_lines([], False), [])

    def test_every_value_is_named_with_its_share_biggest_first(self):
        self.assertEqual(
            _agreed_lines(["39", "(none)", "(none)", "(none)"], False),
            ["(none) (3 of 4)", "39 (1 of 4)"])

    def test_a_blank_reading_is_counted_rather_than_dropped(self):
        """"Nothing recorded, on two of the three" is a measurement. A line carrying only a
        count would read as a count with no value."""
        self.assertEqual(_agreed_lines(["12", "", ""], False),
                         [f"{NO_VALUE} (2 of 3)", "12 (1 of 3)"])

    def test_a_multi_line_value_is_annotated_once(self):
        """`any` expands to the addresses it covers, on a second line. The count belongs to the
        value, so it goes on the value's first line and not on a line of its own."""
        self.assertEqual(
            _agreed_lines(["any\n(4,294,967,296 addresses)",
                           "10.0.0.0/8\n(16,777,216 addresses)"], False),
            ["10.0.0.0/8 (1 of 2)", "(16,777,216 addresses)",
             "any (1 of 2)", "(4,294,967,296 addresses)"])

    def test_a_set_column_counts_its_members_and_not_its_sets(self):
        """Counting the sets prints `ftp` twice with a count against each and never says that
        what differs is the `smtp` one of them also offers."""
        self.assertEqual(_agreed_lines(["ftp, smtp", "ftp"], True),
                         ["ftp", "smtp (1 of 2)"])

    def test_a_set_member_every_object_holds_carries_no_count(self):
        self.assertEqual(_agreed_lines(["group1, group2", "group2, group1"], True),
                         ["group1", "group2"])

    def test_a_member_one_object_lists_twice_is_one_object(self):
        self.assertEqual(_agreed_lines(["ftp, ftp, smtp", "ftp"], True),
                         ["ftp", "smtp (1 of 2)"])

    def test_an_agreed_set_keeps_the_readers_order(self):
        """The order of an offer set means something - `group2 (weakest on offer)` is read in
        the list it belongs to - so agreement does not sort it."""
        self.assertEqual(_agreed_lines(["group14, group2, group5"] * 3, True),
                         ["group14", "group2", "group5"])
