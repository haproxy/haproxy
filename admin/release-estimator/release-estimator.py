#!/usr/bin/python3
#
# Release estimator for HAProxy
#
# A tool that monitors the HAProxy stable branches and calculates a proposed
# release date for the next minor release based on the bug fixes that are in
# the queue.
#
# Copyright 2020 HAProxy Technologies, Daniel Corbett <dcorbett@haproxy.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 3 of the License, or (at your option) any later version.
#
#

from lxml import html
import requests
import traceback
import smtplib
import math
import copy
import time
import sys
import argparse
from datetime import datetime
from datetime import timedelta
from email.mime.text import MIMEText

# Do not report on versions older than
# MAX_VERSION_AGE.
MAX_VERSION_AGE = 1095 # days

# Do not report on non-lts releases (odd releases) that
# are older than MAX_VERSION_AGE_NONLTS
MAX_VERSION_AGE_NONLTS = 547 # days

# For each severity/issue type, set thresholds
# count - indicates how many bugs for this issue type should be in the queue
# time - indicates how many days should be added to the release date
THRESHOLDS = {
    'BUG' :{ 'count' : 1, 'time' : 28},
    'BUILD' :{ 'count' : 1, 'time' : 28},
    'MINOR' : { 'count' : 1, 'time' : 28},
    'MEDIUM' : { 'count' : 1, 'time' : 30},
    'MAJOR' : { 'count' : 1, 'time' : 14 },
    'CRITICAL' : { 'count' : 1, 'time' : 2 }
}

# Increase the urgency of a release as estimated time (in days) gets closer.
RELEASE_URGENCY = { 'WARNING' : 7, 'NOTICE' : 21, 'INFO' : '' }

def search_set(s, f):
    for t in s:
        if f in t:
            return True

def check_for_email(s, parser):
    if "@" not in s:
        parser.print_help()
        sys.exit()

def main():
    global MAX_VERSION_AGE
    global MAX_VERSION_AGE_NONLTS
    global THRESHOLDS
    global RELEASE_URGENCY

    SEND_MAIL=False
    VERSIONS = []
    issues = {}
    BUGQUEUE = {}
    BUGS = { "bugs" :[] }
    email_message = """Hi,

This is a friendly bot that watches fixes pending for the next haproxy-stable release!  One such e-mail is sent periodically once patches are waiting in the last maintenance branch, and an ideal release date is computed based on the severity of these fixes and their merge date.  Responses to this mail must be sent to the mailing list.

"""

    parser = argparse.ArgumentParser(description='HAProxy Stable Release Estimator')
    parser.add_argument('--print', action="store_true",
                        help='Print email only')
    parser.add_argument('--to-email', nargs=1, required=False,
                        help='Send email to <email>')
    parser.add_argument('--from-email', nargs=1, required=False,
                        help='Send email from <email>')
    parser.add_argument('--send-mail', action="store_true",
                        help='Send email')
    args = parser.parse_args()

    if not args.print and not args.send_mail and not args.to_email and not args.from_email:
        parser.print_help()
        sys.exit()

    if args.send_mail and (not args.to_email or not args.from_email):
        parser.print_help()
        sys.exit()

    if args.to_email:
        check_for_email(args.to_email[0], parser)
        TO_EMAIL = args.to_email[0]

    if args.from_email:
        check_for_email(args.from_email[0], parser)
        FROM_EMAIL = args.from_email[0]

    if args.send_mail:
        SEND_MAIL = True

    if SEND_MAIL:
        try:
            TO_EMAIL
            FROM_EMAIL
        except:
            parser.print_help()
            sys.exit()

    #
    # Let's get the list of the current stable versions
    #

    page = requests.get('http://www.haproxy.org/bugs/')
    tree = html.fromstring(page.content)

    for x in (tree.xpath('//th')):
        if x.xpath('./a/text()'):
            VERSIONS.append(x.xpath('./a/text()')[0])


    #
    # For each version let's check it's age. We'll apply the following logic:
    #  - Skip the release if it's:
    #    * older than MAX_VERSION_AGE days
    #    * older than MAX_VERSION_AGE_NONLTS days and an odd numbered release (1.9,2.1,2.3)
    #
    # For all other valid releases we will then collect the number of bug fixes
    # in queue for each of the defined severity levels:
    #  - BUG
    #  - BUILD
    #  - MINOR
    #  - MEDIUM
    #  - MAJOR
    #  - CRITICAL
    #
    # We'll then begin calculating the proposed release date based on the last
    # release date plus the first commit date of the first bug fix for the defined
    # severity level.
    #
    # By default the proposed release dates use the following padding:
    #  (Can be modified in THRESHOLDS)
    #  - BUG/BUILD/MINOR - 28 days
    #  - MEDIUM - 30 days
    #  - MAJOR - 14 days
    #  - CRITICAL - 2 days
    #
    # After we have a proposed release date we will assign a release urgency
    # to it. As we get closer to the proposed release date the urgency level changes.
    # By default the urgency levels and their times are:
    #  - WARNING - proposed date is 7 days or less
    #  - NOTICE  - proposed date is 21 days or less
    #  - INFO    - proposed date is longer than the above
    #

    for version in VERSIONS:
        BUGQUEUE[version] = { "total" : 0, "last": ""  }
        VERSION_THRESHOLDS = copy.deepcopy(THRESHOLDS)
        print("Collecting information on %s" % (version))
        page = requests.get('http://www.haproxy.org/bugs/bugs-%s.html' % (version))
        tree = html.fromstring(page.content)

        issues[version] = {}
        issues_count = {}
        release_soon = False
        num_to_word = {
            1 : 'one',
            2 : 'two',
            3 : 'three',
            4 : 'four',
            5 : 'five',
            6 : 'six',
            7 : 'seven',
            8 : 'eight',
            9 : 'nine',
            10 : 'ten',
            11 : 'eleven',
            12 : 'twelve',
            13 : 'thirteen',
        }

        # parse out the CHANGELOG link
        CHANGELOG = tree.xpath('//a[contains(@href,"CHANGELOG")]/@href')[0]

        last_version = tree.xpath('//td[contains(text(), "last")]/../td/a/text()')[0]
        first_version = "%s.0" % (version)

        # Get CHANGELOG for release
        changelog_page = requests.get(CHANGELOG)
        try:
            for l in changelog_page.content.decode('utf-8').split('\n'):
                # the below is a bit of a hack to parse out valid years in the CHANGELOG
                if (last_version in l) and ('201' in l or '202' in l or '200' in l) and '/' in l:
                    # set the date in which this version was last released
                    last_release_date = l.split(' ')[0]
                    last_release_datetime = datetime.strptime(last_release_date.strip(), '%Y/%m/%d')
                    BUGQUEUE[version]['last'] = last_release_date
                    break
            for l in changelog_page.content.decode('utf-8').split('\n'):
                 # the below is a bit of a hack to parse out valid years in the CHANGELOG
                 if (first_version in l) and ('201' in l or '202' in l or '200' in l) and '/' in l:
                     # set the date in which this version was first released
                     first_release_date = l.split(' ')[0]
                     first_release_datetime = datetime.strptime(first_release_date.strip(), '%Y/%m/%d')
                     BUGQUEUE[version]['first'] = first_release_datetime
                     break
        except:
            print(traceback.format_exc())
            last_release_date = False

        # get unix timestamp for today and timestamp of first release date
        today_ts = datetime.today().timestamp()
        first_version_ts = BUGQUEUE[version]['first'].timestamp()

        # calculate the age of this version in days and years
        version_age = math.ceil((today_ts-first_version_ts)/86400)
        version_age_years = math.ceil(version_age/365)

        # We do not want to monitor versions that are older
        # than MAX_VERSION_AGE or MAX_VERSION_AGE_NONLTS
        if version_age >= MAX_VERSION_AGE:
            print("\t - Version: %s is older than %d days, skipping" % (version, MAX_VERSION_AGE))
            continue

        if version_age > MAX_VERSION_AGE_NONLTS:
            if int(version.split('.')[1]) % 2 > 0:
                print("\t - Version: %s is not LTS and is older than %d days, skipping" % (version, MAX_VERSION_AGE_NONLTS))
                continue

        # If the release is older than 1 year let's increase the time until
        # a release is due. <base time threshold> * <version age years>
        if version_age_years > 1:
            for k in VERSION_THRESHOLDS.keys():
                VERSION_THRESHOLDS[k]['time'] *= int(version_age_years)

        # Let's capture the bug table which contains each bug & their severity
        bug_table = tree.xpath('//th[contains(text(), "Severity")]/ancestor::table[last()]')[0]

        # Loop through bug table and parse out the title of each bug
        # found within the links and their merge date.
        # Example is: 2020-10-19 BUG/MINOR: disable dynamic OCSP load with BoringSSL
        for x in bug_table.xpath('.//a[contains(@href,"commitdiff")]'):
            # Capture the bug label
            # Example: BUG/MINOR: disable dynamic OCSP load with BoringSSL
            issue_tmp = x.xpath('./text()')[0]
            # Capture the date
            # Example: 2020-10-19
            date_tmp = x.xpath('../preceding-sibling::td/text()')[0]

            # Split the bug into a severity
            if "/" in issue_tmp:
                bug_type = issue_tmp.split(':')[0].split('/')[1].strip()
            else:
                bug_type = issue_tmp.split(':')[0].strip()
            bug_text = ":".join(issue_tmp.split(':')[1:]).strip()
            if bug_type not in issues[version].keys():
                issues[version][bug_type] = set()
            issues[version][bug_type].add("%s|%s" % (date_tmp, bug_text))

        # Loop through the issue_types (severities) (MINOR, MEDIUM, MAJOR, etc.)
        # We'll check if the severity has already been accounted for
        # If not, we'll set the timestamp to the timestamp of the current issue
        # If so, we'll check if the current bugs timestamp is less than the
        # previous one. This will help us to determine when we first saw this
        # severity type as calculations are based on the first time seeing a
        # severity type. We'll then set the number of issues for each severity.
        for issue_type in issues[version]:
            issues_count[issue_type] = {}
            for k in issues[version][issue_type]:
                if 'timestamp' not in issues_count[issue_type].keys():
                    issues_count[issue_type]['timestamp'] = int(time.mktime(datetime.strptime(k.split('|')[0], "%Y-%m-%d").timetuple()))
                else:
                    if issues_count[issue_type]['timestamp'] > int(time.mktime(datetime.strptime(k.split('|')[0], "%Y-%m-%d").timetuple())):
                        issues_count[issue_type]['timestamp'] = int(time.mktime(datetime.strptime(k.split('|')[0], "%Y-%m-%d").timetuple()))
            issues_count[issue_type]['count'] = len(issues[version][issue_type])

        release_date = None
        total_count = 0

        # Let's check the count for each severity type and see if they
        # are greater than our thresholds count. This can be used to
        # hold off on calculating release estimates until a certain number of
        # MINOR bugs have accumulated.
        for issue_type in issues_count.keys():
            if issues_count[issue_type]['count'] >= VERSION_THRESHOLDS[issue_type]['count']:
                # If the total number of issues is greater than the threshold
                # for a severity we'll attempt to set a release date.
                # We'll use the timestamp from the first time an issue was
                # seen and add on the number of days specified within the
                # THRESHOLDS for that issue type. We'll also increment
                # the total number of issues that have been fixed in this
                # version across all severities/issue types.
                total_count += issues_count[issue_type]['count']
                issue_timestamp_delta = datetime.fromtimestamp(int(issues_count[issue_type]['timestamp'])) + timedelta(days=int(VERSION_THRESHOLDS[issue_type]['time']))
                if not release_date: release_date = issue_timestamp_delta
                elif release_date > issue_timestamp_delta: release_date = issue_timestamp_delta

        if release_date: release_soon = True
        if release_soon:
            time_until_release = release_date - datetime.now()

        # If a release date has been sent, let's calculate how long
        # in words until that release. i.e. "less than 2 weeks"
        if release_soon:
            for k in sorted(RELEASE_URGENCY.keys()):
                if not RELEASE_URGENCY[k]:
                    release_urgency_msg = k
                elif time_until_release.days <= RELEASE_URGENCY[k]:
                    release_urgency_msg = k
            rounded_week_time = math.ceil(time_until_release.days/7.0)
            if abs(rounded_week_time) > 1:
                week_word = 'weeks'
            else:
                week_word = 'week'
            try:
                # We now have all of the required information for building
                # the email message.
                # TODO: Fix alignment
                email_message = """%s
    Last release %s was issued on %s.  There are currently %d patches in the queue cut down this way:
""" % (email_message, last_version, last_release_datetime.strftime("%Y-%m-%d"), total_count)
                for issue_type in sorted(issues_count.keys()):
                    email_message = "%s    - %d %s, first one merged on %s\n" % (email_message, issues_count[issue_type]['count'],issue_type,datetime.fromtimestamp(int(issues_count[issue_type]['timestamp'])).strftime("%Y-%m-%d"))
                email_message = "%s\nThus the computed ideal release date for %s would be %s, " % (email_message, ".".join(last_version.split(".")[:-1])+"."+str(int(last_version.split(".")[-1])+1), release_date.strftime("%Y-%m-%d"))
                if rounded_week_time < 0:
                    email_message = "%swhich was %s %s ago.\n" % (email_message, num_to_word[abs(rounded_week_time)], week_word)
                elif rounded_week_time == 0:
                    email_message = "%swhich was within the last week.\n" % (email_message)
                else:
                    email_message = "%swhich is in %s %s or less.\n" % (email_message, num_to_word[rounded_week_time], week_word)
            except Exception as err:
                print(traceback.format_exc())
                sys.exit()
            # Total number of bugs fixed in this version
            # since last release.
            BUGQUEUE[version]['total'] = total_count

    email_subject = "stable-bot: Bugfixes waiting for a release "

    # Add each version & their number of bugs to the subject
    for k in sorted(BUGQUEUE.keys(), reverse=True):
        if BUGQUEUE[k]['total'] > 0:
            email_subject = "%s %s (%d)," % ( email_subject, k, BUGQUEUE[k]['total'])

    email_subject = email_subject.rstrip(",")
    email_message = "%s\nThe current list of patches in the queue is:\n" % (email_message)
    uniq_issues = set()

    # Parse out unique issues across all versions so that we can
    # print them once with the list of affected versions.
    for k in BUGQUEUE.keys():
        for issue_type in sorted(issues[k].keys()):
            for issue in issues[k][issue_type]:
                uniq_issues.add("%s|%s" % (issue_type,issue.split('|')[1]))

    # Loop through the unique issues and determine which versions
    # are affected.
    for i in uniq_issues:
        affected_versions = []
        for k in BUGQUEUE.keys():
            try:
                if search_set(issues[k][i.split('|')[0]], i.split('|')[1]):
                    affected_versions.append(k)
            except Exception as e:
                pass
        if affected_versions:
            affected_versions.sort()
            try:
                BUGS["bugs"].append({ "affected_versions" : affected_versions, "bug":i.split('|')[1], "severity":i.split('|')[0] })
            except:
                BUGS["bugs"] = [ { "affected_versions" : affected_versions, "bug":i.split('|')[1], "severity":i.split('|')[0] } ]

    BUGS["bugs"] = sorted(BUGS["bugs"], key = lambda i: i['severity'])

    # Add each issue with affected versions to email message
    # Example:
    # - 1.8, 2.0, 2.1, 2.2 - MINOR   : stats: fix validity of the json schema
    for bug in BUGS["bugs"]:
        email_message = "%s - %s %s %s : %s\n" % (email_message, ", ".join(bug["affected_versions"]).ljust(14), "-".rjust(12), bug["severity"].ljust(7), bug["bug"])

    email_message="%s\n-- \nThe haproxy stable-bot is freely provided by HAProxy Technologies to help improve the quality of each HAProxy release.  If you have any issue with these emails or if you want to suggest some improvements, please post them on the list so that the solutions suiting the most users can be found.\n" % (email_message)

    # If a message with actual issues exists let's either print it or send out
    # an email.
    if "first one merged on" in  email_message:
        if args.print:
            print(email_subject)
            print(email_message)
        if SEND_MAIL:
            print('Send email to:%s from:%s' % (TO_EMAIL, FROM_EMAIL), end="")
            msg = MIMEText(email_message)
            msg['to'] = TO_EMAIL
            msg['from'] = FROM_EMAIL
            msg['subject'] = email_subject
            msg.add_header('reply-to', TO_EMAIL)
            try:
                server = smtplib.SMTP('127.0.0.1', timeout=10)
                server.sendmail(msg['from'], [msg['to']], msg.as_string())
                print(" - Email sent")
            except (ConnectionRefusedError, smtplib.SMTPConnectError):
                print("- Error: SMTP Connection Error")
                sys.exit()
            except smtplib.SMTPServerDisconnected:
                print('- Error: SMTP Server Disconnect (possible timeout)')
                sys.exit()
            except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused):
                print('- Error: Recipients or Sender Refused')
                sys.exit()
            except (smtplib.SMTPHeloError, smtplib.SMTPAuthenticationError):
                print('- Error: SMTP rejected HELO or requires Authentication')
                sys.exit()
            except:
                print(traceback.format_exc())
                sys.exit()


if __name__ == "__main__":
    main()

sys.exit()
