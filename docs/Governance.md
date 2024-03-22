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

Personnel: @dahavey

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
All maintainers should be be listed in the [CODEOWNERS file](../.github/CODEOWNERS).

Personnel: @Alan-Jowett @dv-msft @gtrevi @matthewige @mtfriesen @rectified95 @saxena-anurag @shpalani

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

Personnel: @gtrevi @shpalani @matthewige

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

Personnel: @dthaler @poornagmsft @shankarseal

Minimum Requirements:
* Has acted as a maintainer
* Knows most or all of the maintainers
* Understands the github Admin settings, such as experience from other projects
* Is approved by the existing Project Admins

Responsibilities:
* At least annually, review the current set of personnel in each [role](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization#repository-roles-for-organizations) and update as needed.
* Manage github settings such as branch protection rules and repository secrets.
* Resolve any disputes among maintainers.

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
