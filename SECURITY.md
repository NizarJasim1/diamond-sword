# Security

## Reporting a vulnerability in Diamond Sword itself

If you find a security problem in Diamond Sword itself (for example, a way to make the scope
guard or the transport let a request through to an out-of-scope host, a way to make
a destructive action run without consent, or a way to tamper with the audit log
without `verify` noticing), please don't open a public issue.

Use GitHub's private vulnerability reporting on this repository instead
(**Security → Report a vulnerability**). Include the version or commit, the steps to
reproduce, and what you expected to happen. I'll reply as soon as I can and credit
you in the fix unless you'd rather stay anonymous.

## Using Diamond Sword responsibly

Diamond Sword browses and clicks through a real application with your accounts'
sessions. Treat every run as live testing.

- Only test applications you own, intentionally vulnerable labs, or programs whose
  rules explicitly allow automated testing with multiple accounts.
- Use test accounts you created. Never use other people's credentials.
- Set the scope in the spec as tightly as you can. The scope guard blocks anything
  outside it and treats uncertainty as "don't send".
- Keep read-only on unless the program explicitly allows state changes.
- Don't commit HAR files, principal header files or browser storage states. They
  contain live session credentials.

Bugs you find with Diamond Sword in someone else's product should go to that vendor through
their disclosure process, not here.
