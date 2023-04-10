# Project Governance

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

## Process for creating and servicing a release

Please refer to the [Release Process.md](ReleaseProcess.md) documentation.