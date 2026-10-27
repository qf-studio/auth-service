# TASK-11: ops(db): check prod users for emails that differ only by case before migration 000022 deploys

**Created:** 2026-10-27
**Status:** 📋 Issue #573, assigned to Nelya (human ops task, no `pilot` label)
**Last Updated:** 2026-10-27

## Context

PR #569 (#526) adds migration `000022`: a unique index on `users (tenant_id, lower(email))`. The migration stops with an error if a tenant already has two users whose emails differ only by case. The deploy workflow rolls out the new service code first and runs the migration after it, so on collisions:

- the migrate job fails and the schema stays dirty at version 22;
- the new code is live without the index, and `FindByEmail` (now `lower(email) = lower($1)`) can match either of the two rows, so a password reset can reach the wrong row.

The next release after v0.76.1 contains #569. Its deploy waits for the `aws-quantflow` approval, so the release can be held until this check is done.

Nobody can run the check today: the operator IAM user has `ReadOnlyAccess` but no `ecs:RunTask`, `ecs:RegisterTaskDefinition` or `iam:PassRole`, ECS Exec is off on the service, and the RDS instance is private.

## Implementation Plan

1. **IAM (account admin).** Attach this temporary inline policy to the operator IAM user (`<account-id>` is the quantflow account):

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       { "Sid": "RegisterAndDeregisterTaskDefinition", "Effect": "Allow",
         "Action": ["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition"], "Resource": "*" },
       { "Sid": "RunCheckTaskOnQuantflowCluster", "Effect": "Allow", "Action": "ecs:RunTask",
         "Resource": "arn:aws:ecs:eu-central-1:<account-id>:task-definition/quantflow-auth-collision-check:*",
         "Condition": { "ArnEquals": { "ecs:cluster": "arn:aws:ecs:eu-central-1:<account-id>:cluster/quantflow" } } },
       { "Sid": "StopTaskOnQuantflowCluster", "Effect": "Allow", "Action": "ecs:StopTask",
         "Resource": "arn:aws:ecs:eu-central-1:<account-id>:task/quantflow/*",
         "Condition": { "ArnEquals": { "ecs:cluster": "arn:aws:ecs:eu-central-1:<account-id>:cluster/quantflow" } } },
       { "Sid": "PassExecutionRoleToEcsTasks", "Effect": "Allow", "Action": "iam:PassRole",
         "Resource": "arn:aws:iam::<account-id>:role/quantflow-execution",
         "Condition": { "StringEquals": { "iam:PassedToService": "ecs-tasks.amazonaws.com" } } }
     ]
   }
   ```

   Access Analyzer `validate-policy` returns no findings for it.
2. **Run the check (operator).** A local script registers a one-off task definition `quantflow-auth-collision-check` (pinned `postgres:16-alpine` digest, DB credentials injected from the existing DB secret by the execution role, `default_transaction_read_only=on`, 30 s statement timeout), runs one task on the `quantflow` cluster, prints the result from the service log group, and deregisters the task definition on exit. The query prints three counts and no email address:

   ```sql
   SELECT count(*) AS groups, coalesce(sum(n),0) AS rows_involved, coalesce(sum(active),0) AS active_rows
   FROM (SELECT count(*) n, count(*) FILTER (WHERE deleted_at IS NULL) active
         FROM users GROUP BY tenant_id, lower(email) HAVING count(*) > 1) d;
   ```

   The task definition and script are kept outside the repo (they contain account-specific ARNs).
3. **Remove the policy (account admin)** right after the run.
4. **Decide:** `groups = 0` → approve the release deploy. `groups > 0` → resolve those accounts by hand first (see "Case-Insensitive Email Uniqueness (migration 000022)" in `deployments/README.md`), then approve.

## Technical Decisions

- A one-off ECS task, not a port forward: the DB password never leaves AWS, and the task runs in the same network path as the migrations.
- Read-only at the session level (`default_transaction_read_only=on`), counts only in the logs (no personal data).
- The policy is scoped to one task-definition family, one cluster and one role, and is removed after the run.

## Dependencies

- Must finish before the deploy of the release that contains #569 is approved.

## Verify

- The log shows `transaction_read_only = on` and one row of counts; the task exits with code 0.
- The task definition is deregistered and the inline policy is removed.

## Done

- The counts are posted on this issue, the policy is removed, and the release deploy is approved or the collisions are resolved.

## Refs

- Issue: https://github.com/qf-studio/auth-service/issues/573
- PR #569 (#526), `deployments/README.md` (migration 000022 recovery).
