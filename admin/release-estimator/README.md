# Release Estimator
This tool monitors the HAProxy stable branches and calculates a proposed
release date for the next minor release based on the bug fixes that are in
the queue.


## Requirements
  - Python 3.x
  - [lxml](https://lxml.de/installation.html)


## Usage
    release-estimator.py [-h] [--print] [--to-email TO_EMAIL]
                               [--from-email FROM_EMAIL] [--send-mail]

    optional arguments:
      -h, --help            show this help message and exit
      --print               Print email only
      --to-email TO_EMAIL   Send email to <email>
      --from-email FROM_EMAIL
                            Send email from <email>
      --send-mail           Send email


## Examples


### Print only:
    ./release-estimator.py --print


### Send email:
    ./release-estimator.py --send-mail --from-email from@domain.local --to-email to@domain.local


## How it works
For each version we check the age and apply the following logic:
  - Skip the release if it's:
      - older than MAX_VERSION_AGE
      - older than MAX_VERSION_AGE_NONLTS days and an odd numbered release
        (1.9,2.1,2.3)

  - For all other valid releases we will then collect the number of bug fixes
    in queue for each of the defined severity levels:
      - BUG
      - BUILD
      - MINOR
      - MEDIUM
      - MAJOR
      - CRITICAL

    We'll then begin calculating the proposed release date based on the last
    release date plus the first commit date of the first bug fix for the defined
    severity level.

    By default the proposed release dates use the following padding:
    (Can be modified in THRESHOLDS)
      - BUG/BUILD/MINOR - 28 days
      - MEDIUM - 30 days
      - MAJOR - 14 days
      - CRITICAL - 2 days

    After we have a proposed release date we will assign a release urgency
    to it. As we get closer to the proposed release date the urgency level changes.
    By default the urgency levels and their times are:
      - WARNING - proposed date is 7 days or less
      - NOTICE  - proposed date is 21 days or less
      - INFO    - proposed date is longer than the above
