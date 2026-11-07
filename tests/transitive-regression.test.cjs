const {test} = require('node:test');
const assert = require('node:assert/strict');
const {mkdtempSync, writeFileSync, rmSync} = require('node:fs');
const {tmpdir} = require('node:os');
const {join} = require('node:path');
const {parseAudit, shouldFail} = require('../bin/analyzer.js');
const {scanProject} = require('../bin/scanner.js');

const audit = JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {
    lodash: {
      name: 'lodash',
      severity: 'high',
      isDirect: false,
      range: '<4.17.21',
      via: [{name:'lodash', title:'CVE-2021-23337: command injection'}, 'upstream-parent'],
      fixAvailable: {name:'upstream-parent', version:'2.0.0', isSemVerMajor:true}
    },
    'upstream-parent': {
      name:'upstream-parent', severity:'moderate', isDirect:true, range:'*',
      via:['lodash'], fixAvailable:false
    }
  }
});

test('transitive known-advisory fixture retains chain and upgrade boundary', () => {
  const report = parseAudit(audit);
  assert.equal(report.counts.total, 2);
  assert.equal(report.counts.high, 1);
  assert.equal(report.packages[0].name, 'lodash');
  assert.equal(report.packages[0].isDirect, false);
  assert.deepEqual(report.packages[0].via, ['CVE-2021-23337: command injection', 'upstream-parent']);
  assert.deepEqual(report.packages[0].fixAvailable,
    {name:'upstream-parent', version:'2.0.0', isSemVerMajor:true});
  assert.equal(shouldFail(report,'high'), true);
  assert.equal(shouldFail(report,'critical'), false);
});

test('audit exit code one with a transitive vulnerability is a finding, not an npm failure', async () => {
  const dir=mkdtempSync(join(tmpdir(),'depscanx-transitive-'));
  try {
    writeFileSync(join(dir,'package.json'),'{}');
    writeFileSync(join(dir,'package-lock.json'),'{}');
    const result=await scanProject(dir,{outdated:false,timeoutMs:5000},
      async () => ({code:1,stdout:audit,stderr:''}));
    assert.equal(result.audit.packages.find(x=>x.name==='lodash').isDirect,false);
    assert.equal(result.audit.counts.total,2);
  } finally {rmSync(dir,{recursive:true,force:true});}
});

test('malformed npm audit data fails closed even with success or vulnerability exit code', async () => {
  const dir=mkdtempSync(join(tmpdir(),'depscanx-malformed-'));
  try {
    writeFileSync(join(dir,'package.json'),'{}');
    writeFileSync(join(dir,'package-lock.json'),'{}');
    for (const code of [0,1]) {
      await assert.rejects(
        scanProject(dir,{outdated:false,timeoutMs:5000},
          async () => ({code,stdout:'{"error":{"summary":"registry unavailable"}}',stderr:''})),
        /relatório de vulnerabilidades válido/);
    }
  } finally {rmSync(dir,{recursive:true,force:true});}
});
