/**
 * Permission strings for automation, software and patching (`Dranzo.Domain.Permissions`) that the shared `P` map
 * in `lib/auth/permissions.ts` does not list. The UI only uses them to hide actions; the server enforces them.
 */
export const AP = {
  scriptsRead: 'scripts.read',
  scriptsManage: 'scripts.manage',
  scriptsRun: 'scripts.run',
  jobsRead: 'jobs.read',
  jobsCancel: 'jobs.cancel',
  softwareRead: 'software.read',
  softwareDeploy: 'software.deploy',
  packagesManage: 'packages.manage',
  patchesRead: 'patches.read',
  patchesApprove: 'patches.approve',
  patchesInstall: 'patches.install',
} as const;
