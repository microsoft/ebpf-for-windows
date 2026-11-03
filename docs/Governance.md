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
* Is approved by the existing [Project Admins](#project-admin)

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
* Is approved by the existing [Project Admins](#project-admin)

Responsibilities:
* Run the weekly [triage meetings](https://github.com/microsoft/ebpf-for-windows/discussions/427).
* If the triage meeting is canceled (e.g., due to a holiday),
  announce that fact in the [github discussion thread](https://github.com/microsoft/ebpf-for-windows/discussions/427).

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
* Is approved by the existing [Project Admins](#project-admin)

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
* Is approved by the existing [Project Admins](#project-admin)

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
At any given month, the project will have two `YYMM` milestones, for the current and next month,
along with the `Future` and `Backlog` milestones.
The [Future milestone](https://github.com/microsoft/ebpf-for-windows/milestone/78) is the default for most untriaged bugs.
At the end of a monthly milestone, issues from `Future` can be moved to a milestone associated with a `YYMM`.
The `Backlog` milestone exists for backlog issues.

## Issues Triage

Maintainers triage new issues in the weekly Monday
[issues triage meeting](https://github.com/microsoft/ebpf-for-windows/discussions/427)
and assign them to milestones following the [issue priority guidelines](#prioritizing-issues) below.
Maintainers may change an issue's priority as business priorities change.

### Prioritizing Issues

To help prioritize issues, the triage drivers and maintainers MUST use *GitHub Priority fields* to prioritize issues as follows:
#### Urgent:
This priority represents the highest priority and is reserved for critical issues that are causing catastrophic impact
to customers or blocking development altogether. Urgent priority issues MUST be set to the current `YYMM` milestone.
Only these critical issues are assigned directly to the current milestone during triage; other issues are scheduled
through [milestone planning](#planning-for-a-milestone).
#### High:
This priority should ONLY be applied to bugs or features with quantifiable business impact. Quantifiable business impact
may include number of users, business blocked, or deployment blocked. Bugs with only qualitative impact (descriptions
without numbers) will be ranked lower than quantifiable Urgent or High priority bugs.
High priority issues are assigned to the `Future` milestone until selected during milestone planning.
#### Medium:
This priority is used for the next level of priority.
Medium priority issues are assigned to the `Future` milestone until selected during milestone planning.
#### Low:
This priority is used for low priority issues. Low priority issues can be assigned to the `Future` or `Backlog` milestone.

## Closing Active Issues

* Follow GitHub guidelines on [closing an issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/administering-issues/closing-an-issue).
* Follow GitHub guidelines on [closing duplicate issues](https://github.blog/changelog/2024-12-12-github-issues-projects-close-issue-as-a-duplicate-rest-api-for-sub-issues-and-more/#broom-close-an-issue-as-a-duplicate).
* Issues for bugs that cannot be reproduced can be closed as "not planned" after providing relevant details (such as trace logs etc.).
* Closing an issue for any other reason, including (but not limited to) not fixing the bug, or not completing the task
 requires discussion in a triage meeting, and should not be done purely due to lack of resources for which case moving
 to Low priority, and putting a label of "Help Wanted, Backlog" is preferred. Closing an issue as "*Won't Fix*" is appropriate when it is decided that
 the proposal is (or no longer is) a good idea to be done at all.

## Planning for a Milestone

In the first triage meeting of the month, leftover open issues from the previous `YYMM` milestone
will move to the current `YYMM` milestone. Maintainers will then bring issues from `Future` into the current
`YYMM` milestone, subject to the remaining contributor capacity.
High priority issues take precedence over Medium priority issues. Within the same priority, older issues take
precedence over newer issues.

Maintainers need to ensure that the number of issues in a monthly milestone reflects the capacity of the contributors
actively working on the project. At the end of each triage meeting, the
[Project Milestones](https://github.com/microsoft/ebpf-for-windows/milestones)
should be checked to avoid overcommitting the monthly milestones.
Capacity depends on the number of active contributors, the complexity of the issues, and other relevant factors
as deemed important by the maintainers.
As a rule of thumb, plan for roughly 2 issues per active contributor per month.
For example, 5 active contributors would have capacity for roughly 10 issues per monthly milestone.
This capacity guideline applies to `YYMM` milestones, not `Future` or `Backlog`.

**Note:** Capacity includes both open and closed issues. Closing an issue does not "add room" for more issues in the milestone.

## Closing a Milestone

In the first triage meeting of a month, the previous `YYMM` milestone must be closed after moving its leftover open
issues to the current `YYMM` milestone as described in [Planning for a Milestone](#planning-for-a-milestone).

If any issue has been moved two times already, then the issue must be re-triaged for setting the appropriate priority and/or the milestone.

## Reviewing Pull Requests

Pull requests need at least two approvals before being eligible for merging.
Besides reviewing for technical correctness, reviewers are expected to:

* For any PR that adds functionality, check that the PR includes sufficient tests
  for that functionality.  This is required in [CONTRIBUTING.md](../CONTRIBUTING.md).
* For any PR that adds or changes functionality in a way that is observable
  by administrators or by authors of eBPF programs or applications, check that
  documentation has been sufficiently updated.  This is required in
  [CONTRIBUTING.md](../CONTRIBUTING.md).
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
