const { createLdapClient } = require('@naze/ldap-client');
const config = require('../config');

const SEARCH_ATTRS = ['uid', 'cn', 'mail', 'displayName', 'memberOf', 'objectClass'];

let adminClient = null;

async function getAdminClient() {
  if (adminClient) {
    return adminClient;
  }
  const client = createLdapClient(config.ldap.url);
  const result = await client.bind(config.ldap.bindDN, config.ldap.bindPassword);
  if (!result.success) {
    throw new Error(`LDAP bind failed: ${result.error}`);
  }
  client.onError = () => {
    adminClient = null;
  };
  adminClient = client;
  return client;
}

function mapEntry(entry) {
  const attrs = entry.attributes || {};
  const getArr = (val) => {
    if (!val) return [];
    return Array.isArray(val) ? val : [val];
  };
  return {
    dn: entry.dn,
    username: attrs.uid || attrs.cn || '',
    displayName: attrs.cn || attrs.displayName || '',
    email: attrs.mail || null,
    groups: getArr(attrs.memberOf),
    objectClass: getArr(attrs.objectClass),
  };
}

async function authenticate(username, password) {
  const client = await getAdminClient();
  const filter = config.ldap.userSearchFilter.replace('{{username}}', username);
  const searchResult = await client.search(config.ldap.userSearchBase, filter, SEARCH_ATTRS);

  if (!searchResult.success || !searchResult.entries || searchResult.entries.length === 0) {
    throw new Error('Invalid credentials');
  }

  const userEntry = searchResult.entries[0];
  const userDN = userEntry.dn;

  const userClient = createLdapClient(config.ldap.url);
  const bindResult = await userClient.bind(userDN, password);
  userClient.unbind();

  if (!bindResult.success) {
    throw new Error('Invalid credentials');
  }

  const attrs = userEntry.attributes || {};
  const getArr = (val) => {
    if (!val) return [];
    return Array.isArray(val) ? val : [val];
  };

  return {
    dn: userDN,
    username: attrs.uid || attrs.cn || username,
    displayName: attrs.cn || attrs.displayName || username,
    email: attrs.mail || null,
    groups: getArr(attrs.memberOf),
  };
}

async function getUser(username) {
  const client = await getAdminClient();
  const filter = config.ldap.userSearchFilter.replace('{{username}}', username);
  const result = await client.search(config.ldap.userSearchBase, filter, SEARCH_ATTRS);

  if (!result.success || !result.entries || result.entries.length === 0) {
    throw new Error('User not found');
  }

  return mapEntry(result.entries[0]);
}

async function searchUsers(keyword, sizeLimit = 50) {
  const client = await getAdminClient();
  let filter;
  if (keyword) {
    filter = `(|(uid=*${keyword}*)(cn=*${keyword}*)(mail=*${keyword}*)(displayName=*${keyword}*))`;
  } else {
    filter = '(objectClass=*)';
  }

  const result = await client.search(config.ldap.userSearchBase, filter, SEARCH_ATTRS);

  if (!result.success) {
    throw new Error('LDAP search failed');
  }

  const entries = (result.entries || []).map(mapEntry);
  return entries.slice(0, sizeLimit);
}

module.exports = { authenticate, getUser, searchUsers };
