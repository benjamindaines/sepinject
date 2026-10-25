"""Shared test fixtures: a small, self-contained synthetic CIL policy.

The synthetic policy is deliberately tiny and fully controlled so assertions do not depend on the internals of
any real device policy. It declares two domains, one attribute, one class with two permissions, and one
neverallow, which is enough to exercise universe loading, completions, diagnostics, and neverallow conflict
detection.
"""

SYNTH_CIL = """\
(class file (read write open getattr))
(common ipc (create destroy))
(classcommon sem ipc)
(class sem (associate))
(type domain_a)
(type domain_b)
(type file_x)
(typeattribute app_domain)
(typeattributeset app_domain (domain_a domain_b))
(neverallow app_domain file_x (file (write)))
(genfscon proc "/sys/x" (u object_r file_x ((s0) (s0))))
"""
