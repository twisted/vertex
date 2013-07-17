Coding Standard
===============

Vertex follows the [Twisted Coding Standard](https://twistedmatrix.com/documents/current/core/development/policy/coding-standard.html).
Although it has not currently incorporated as a checker, the [Twisted Coding Standard Checker](https://launchpad.net/twistedchecker) would be a useful tool.


Testing Standard
================

Please make sure that all new code is tested according to the [Twisted Test Standard](https://twistedmatrix.com/documents/current/core/development/policy/test-standard.html) and has complete coverage.

[travis-ci](https://travis-ci.org/twisted/vertex) is used to make sure that tests keep passing

Please document test cases and methods with useful, relevant docstrings stated in a present tense and in the active voice.
[This post](https://plus.google.com/115348217455779620753/posts/YA3ThKWhSAj) has a concise summary of what makes a good test docstring.


Documentation Standard
======================

Please document all public interface methods.

The [Twisted documentation standard](http://twistedmatrix.com/trac/browser/trunk/doc/core/development/policy/writing-standard.xhtml?format=raw) is a good guide on style.


Review Process
==============

Vertex mostly follows the [Twisted review process](http://twistedmatrix.com/trac/wiki/ReviewProcess) for contributions, with some minor changes for working with Github.

Issues
------
Issues should generally be opened first, and pull requests linked to issues for the following reasons:

- Writing the issue first will help clarify what needs to be done for both a contributor and a reviewer
- If a pull request is abandoned, it may be closed without also closing the underlying issue.
- If the work is taken over by someone else, both the old and new pull requests may be linked to the same issue.
- Overall discussion of how to go about resolving the problem may happen in the issue, and code review can happen in a pull request.

Issues should have a meaningful title and description of what needs to change and why.
Although implementation details are not necessarily needed, well-defined completion conditions should be included in the description (in list form would be helpful).


Pull Requests
-------------
Pull requests should be small and self-contained, which makes it easier for the reviewer and may increase review turnaround time.

If one pull request is insufficient to solve the issue (and not because the pull request is then abandoned and taken over by someone else), the issue it is trying to resolve to should be broken up into multiple smaller issues, and the pull request linked to one of them.

All pull requests must be reviewed prior to merging.

There is currently no particular standard as to whether pull requests should be made on branches vs forks.
As such, those who have push access to the repo can use either branches or forks, and everyone else who does not have push access perfoce must use forks.


Reviews
-------
To pass review, pull requests should:

1. follow the stated coding standard
1. have 100% unit test coverage of modified and new code (even if it didn't have tests before)
1. have 100% API docstring coverage for all modified and new code (even if it didn't have docs before)
1. have prose documentation giving a high-level sense of how an API is meant to be used and what capabilities the library offers. 

In addition:

1. All tests must pass - this is enforced with [Travis-CI](https://travis-ci.org/twisted/vertex)
1. Code coverage must not decrease - this is enforced by (and more details available at) [Coveralls](https://coveralls.io/r/twisted/vertex).
Although coverage does not say anything about the quality of the tests or the correct behavior of the tests (both of which should be evaluated during review), it provides a minimal baseline.

Once a pull request is approved, the big green button should be used to merge.

In the merge commit, Github determines the top line of the message, and the title of the pull request is the second line, but can be edited.
Please make sure this second line is meaningful, either by making the pull request title meaningful or by editing the commit message.

Following the second line, the reviewers and a "fixes" should be included, as per the Twisted merge commit messages.  
Finally, a longer description should be added that details the change.

    <Uneditable line re: which branch and pull request are getting merged>
    <Editable second line>
    
    Reviewers <names>
    Fixes #<issue number>

    Long description (as long as you wish)

["Fixes #issue" will close one or more issues](https://help.github.com/articles/closing-issues-via-commit-messages).  Note the lack of colon after the word "Fixes" - if a colon appears after "Fixes", the issue will not be automatically closed.

Once the pull request is merged, if using branches, please delete the branch.
