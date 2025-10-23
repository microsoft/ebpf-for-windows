# Project Governance

## Roles and Personnel

The eBPF for Windows project currently uses the following roles, listed
in order of increasing permission:

* Contributor
* Collaborator
* Triage Driver
* Maintainer
* Release Manager
* Project Admin

Refer to [Repository roles](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization).

### Contributor

The ability to read, clone, and contribute issues or
pull requests is open to the public.

Personnel: anyone

Minimum Requirements: (none)

Responsibilities: (none)

### Collaborator

A collaborator is a contributor who can have issues and pull request
review requests assigned to them in github.
This corresponds to the "Read" role in github.

Personnel: @alessandrogario @evershalik @hawkinsw @song-jiang

Minimum Requirements:
* Has attended a triage meeting
* Has agreed to have a github issue assigned to them to work on
* Is approved by the existing [Project Admins](@project-admin)

Responsibilities:
* Contribute pull requests for any assigned issues

### Triage Driver

A triage driver can also manage issues and pull requests,
including assigning them to others and assigning labels and milestones.
This corresponds to the "Triage" role in github.

Personnel: @mingxr

Minimum Requirements:
* Consistently participates in weekly triage meetings
* Has ability and willingness to share screen in Zoom
* Is approved by the existing [Project Admins](@project-admin)

Responsibilities:
* Run the weekly [triage meetings](https://github.com/microsoft/ebpf-for-windows/discussions/427).
* If the triage meeting is canceled (e.g., due to a holiday),
  announce that fact in the [Slack channel](https://cilium.slack.com/messages/ebpf-for-windows)
  and [github discussion thread](https://github.com/microsoft/ebpf-for-windows/discussions/427).

### Maintainer

A maintainer can also merge pull requests.
This corresponds to the "Write" role in github.
All maintainers must be listed in the [CODEOWNERS file](../.github/CODEOWNERS).

Personnel: @Alan-Jowett @dthaler @LakshK98 @matthewige @mikeagun
@saxena-anurag @shankarseal

Minimum Requirements:
* Consistently participates in weekly [triage meetings](https://github.com/microsoft/ebpf-for-windows/discussions/427)
* Has submitted multiple pull requests across at least 2 months that have been merged
* Has provided feedback on multiple pull requests from others, across at least 2 months
* Has demonstrated an understanding of a particular area of the code such as one or more directories
* Is approved by the existing [Project Admins](@project-admin)

Responsibilities:
* [Review pull requests](#reviewing-pull-requests) from others.
* Merge pull requests once tests pass and sufficient approvals exist.

### Release Manager

In addition to having Maintainer privileges and responsibilities,
a release manager is also responsible for generating releases in github.
The release manager for this project must be a Microsoft full time employee in order to build Microsoft-signed binaries that Windows will load.

Personnel: @Alan-Jowett @LakshK98 @matthewige @mikeagun @saxena-anurag @shankarseal

Minimum Requirements:
* Consistently participates in weekly [triage meetings](https://github.com/microsoft/ebpf-for-windows/discussions/427)
* Has acted as a maintainer for at least 2 months
* Has demonstrated an understanding of MSI installation
* Has demonstrated an understanding of the eBPF for Windows release process
* Has access to the Microsoft signing pipeline
* Is approved by the existing [Project Admins](@project-admin)

Responsibilities:
* Generate periodic releases according to the [Release Process.md](ReleaseProcess.md) documentation.
* Create a milestone for each upcoming release (typically four digits of the form YYMM).

### Project Admin

An admin can also assign people to each of these
roles, and have full access to all github settings.
This corresponds to the "Admin" role in github.

Personnel: @poornagmsft @shankarseal

Minimum Requirements:
* Has acted as a maintainer
* Knows most or all of the maintainers
* Understands the github Admin settings, such as experience from other projects
* Is approved by the existing Project Admins

Responsibilities:
* At least annually, review the current set of personnel in each [role](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization#repository-roles-for-organizations) and update as needed.
* Manage github settings such as branch protection rules and repository secrets.
* Resolve any disputes among maintainers.

## Project Milestones

eBPF for Windows uses monthly milestones in the format `YYMM`. So, e.g., the milestone for June, 2024 will be called 2406.
At any time, there will be one current milestone (for the current month) and one or more future milestones, in the project.
A `Backlog` milestone exists for backlog issues.
In the weekly triage meetings, new issues should be added to a milestone following guidelines in the
[Prioritizing Issues](Governance.md#prioritizing-issues) section.

## Prioritizing Issues

To help prioritize issues, the triage drivers and maintainers MUST use *special labels* to prioritize issues as follows:
### P1:
This label represents highest priority. This label should be used for bugs impacting users, new features, or enhancements that are urgently
requested by users. `P1` issues MUST be set to the *current milestone*.
### P2:
This label is used for the next level of priority. Issues marked as `P2` can be set to the current milestone or to a future milestones (preferred).
### P3:
This label is used for low priority issues. Issues marked as `P3` can be set to any future milestone or the `Backlog` milestone.

## Milestone Issues Limit
Triage managers need to ensure that the number of issues in a milestone does not exceed the capacity of the contributors
actively working on the project. At the end of each triage meeting, the
[Project Milestones](https://github.com/microsoft/ebpf-for-windows/milestones)
should be checked to see if there aren't too many issues added to any given milestone.
The issues limit for a given milestone will depend on number of contributors working on them,
the complexities of the issues and other relevant factors as deemed important by the triage drivers.
As a rule of thumb, the number of issues in a milestone should not exceed 3 times the number of active contributors.
Assuming 6 - 7 active contributors, there should be no more than 20 issues per milestone.

**Note:** This limit is irrespective of the issue state. Closing out an issue, does not "add room" for more issues into the milestone.

A `P2` or `P3` issues must be added to the first milestone that has not reached its limit.
A `P1` issue can only be added to the current milestone (`N`). If adding a new `P1` issue exceeds the milestone limit,
one or more open issues must be moved to the future milestones. Open `P2` and `P3` issues in the current milestone
must the first candidates for moving. If all the open issues in the current milestone are `P1`, the triage drivers
must *downgrade* one or more of them to `P2` and move them to the next (`N+1`) milestone.

If all existing milestones have exceeded their limit issues, a new milestone must be created to accommodate new issues.

## Closing a Milestone
In the first triage meeting of a month, the previous milestone (`N`) must be closed.

Ideally, all issues should be addressed by the end of the designated milestones. However, if that does not happen for any reason,
triage drivers or administrators must move all overdue issues that do not have an active pull request to a future milestone as follows:
  - `P1` issues can be moved to the *next* (`N+1`) milestone. This must be done in a triage meeting, after discussing with all maintainers.
  - `P2` issues can be moved to any of the future milestones.
  - `P3` issues can be moved to future or `Backlog` milestones.

Moving issues to future milestones should not exceed the per milestone issues limit.
If any issue has been moved two times already, then the issue must be re-triaged for setting the appropriate priority and/or the milestone.

## Reviewing Pull Requests

Pull requests need at least two approvals before being eligible for merging.
Besides reviewing for technical correctness, reviewers are expected to:

* For any PR that adds functionality, check that the PR includes sufficient tests
  for that functionality.  This is required in [CONTRIBUTING.md](../Contributing.md).
* For any PR that adds or changes functionality in a way that is observable
  by administrators or by authors of eBPF programs or applications, check that
  documentation has been sufficiently updated.  This is required in
  [CONTRIBUTING.md](../Contributing.md).
* Check that there are no gratuitous differences in public APIs between eBPF for
  Windows and Linux.
* Be familiar with, and call out code that does not conform to, the eBPF for Windows
  [coding conventions](DevelopmentGuide.md).
* Check that errors are appropriately logged where first detected (not at each
  level of stack unwind).

When multiple pull requests are approved, maintainers should prioritize merging PRs as follows:

| Pri | Description  | Tags      | Rationale              |
| --- | ------------ | --------- | ---------------------- |
| 1   | Bugs         | bug       | Affects existing users |
| 2   | Test bugs    | tests bug | Problem that affects CI/CD and may mask priority 1 bugs |
| 3   | Additional tests | tests enhancement | Gap that once filled might surface priority 1 bugs |
| 4   | Documentation | documentation | Won't affect CI/CD but may address usability issues |
| 5   | Dependencies | dependencies | Often a large amount of low hanging fruit. Keeping the overall PR count low gives a better impression to newcomers and observers. |
| 7   | New features | enhancement | Adds new functionality requested in a github issue. Although this typically is lower priority than dependencies, such PRs from new contributors should instead be prioritized above dependencies. |
| 8   | Performance optimizations | optimization | Doesn't do anything that isn't already working, but improvements do help users |
| 9   | Code cleanup | cleanup | Good to do but generally doesn't significantly affect any of the above categories |
