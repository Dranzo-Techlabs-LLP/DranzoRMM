import { describe, expect, it } from 'vitest';
import {
  baseName,
  breadcrumbs,
  defaultPath,
  joinPath,
  normalizePath,
  parentPath,
  pathStyleFor,
  sortEntries,
} from './paths';

describe('file browser paths: POSIX', () => {
  it('normalizes typed paths', () => {
    expect(normalizePath('  /home//ada/ ', 'posix')).toBe('/home/ada');
    expect(normalizePath('', 'posix')).toBe('/');
    expect(normalizePath('/', 'posix')).toBe('/');
  });

  it('builds breadcrumbs from the root', () => {
    expect(breadcrumbs('/var/log/nginx', 'posix')).toEqual([
      { label: '/', path: '/' },
      { label: 'var', path: '/var' },
      { label: 'log', path: '/var/log' },
      { label: 'nginx', path: '/var/log/nginx' },
    ]);
    expect(breadcrumbs('/', 'posix')).toEqual([{ label: '/', path: '/' }]);
  });

  it('joins, goes up and names', () => {
    expect(joinPath('/', 'etc', 'posix')).toBe('/etc');
    expect(joinPath('/etc', 'hosts', 'posix')).toBe('/etc/hosts');
    expect(parentPath('/etc/ssh', 'posix')).toBe('/etc');
    expect(parentPath('/etc', 'posix')).toBe('/');
    expect(parentPath('/', 'posix')).toBeNull();
    expect(baseName('/etc/hosts', 'posix')).toBe('hosts');
  });
});

describe('file browser paths: Windows', () => {
  it('normalizes drive letters, separators and trailing slashes', () => {
    expect(normalizePath('c:', 'windows')).toBe('C:\\');
    expect(normalizePath('c:/Users//ada/', 'windows')).toBe('C:\\Users\\ada');
    expect(normalizePath('\\\\server\\share\\\\docs\\', 'windows')).toBe('\\\\server\\share\\docs');
    expect(defaultPath('windows')).toBe('C:\\');
  });

  it('builds breadcrumbs that start at the drive', () => {
    expect(breadcrumbs('C:\\Users\\ada', 'windows')).toEqual([
      { label: 'C:', path: 'C:\\' },
      { label: 'Users', path: 'C:\\Users' },
      { label: 'ada', path: 'C:\\Users\\ada' },
    ]);
    expect(breadcrumbs('\\\\srv\\share\\x', 'windows')).toEqual([
      { label: '\\\\srv\\share', path: '\\\\srv\\share' },
      { label: 'x', path: '\\\\srv\\share\\x' },
    ]);
  });

  it('stops going up at the drive root or share', () => {
    expect(parentPath('C:\\Users\\ada', 'windows')).toBe('C:\\Users');
    expect(parentPath('C:\\Users', 'windows')).toBe('C:\\');
    expect(parentPath('C:\\', 'windows')).toBeNull();
    expect(parentPath('\\\\srv\\share', 'windows')).toBeNull();
    expect(joinPath('C:\\', 'Windows', 'windows')).toBe('C:\\Windows');
    expect(baseName('C:\\Users\\ada\\notes.txt', 'windows')).toBe('notes.txt');
  });

  it('picks the style by operating system', () => {
    expect(pathStyleFor('windows')).toBe('windows');
    expect(pathStyleFor('macos')).toBe('posix');
  });
});

describe('listing order', () => {
  it('puts folders first, then sorts by name ignoring case', () => {
    const sorted = sortEntries([
      { name: 'b.txt', isDir: false },
      { name: 'Zeta', isDir: true },
      { name: 'A.txt', isDir: false },
      { name: 'alpha', isDir: true },
    ]);
    expect(sorted.map((e) => e.name)).toEqual(['alpha', 'Zeta', 'A.txt', 'b.txt']);
  });
});
