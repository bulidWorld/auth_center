const { createLdapClient } = require('@naze/ldap-client');
const config = require('../config');
const logger = require('../logger');

const SEARCH_ATTRS = ['uid', 'cn', 'mail', 'displayName', 'memberOf', 'objectClass'];

async function getAdminClient() {
  logger.debug('LDAP admin client: connecting', { url: config.ldap.url });
  const client = createLdapClient(config.ldap.url);
  const result = await client.bind(config.ldap.bindDN, config.ldap.bindPassword);
  if (!result.success) {
    logger.error('LDAP admin bind failed', { error: result.error });
    throw new Error(`LDAP bind failed: ${result.error}`);
  }
  logger.debug('LDAP admin bind succeeded');
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
  logger.debug('LDAP authenticate start', { username });
  const client = await getAdminClient();
  try {
    const filter = config.ldap.userSearchFilter.replace('{{username}}', username);
    logger.debug('LDAP search user', { base: config.ldap.userSearchBase, filter });
    const searchResult = await client.search(config.ldap.userSearchBase, filter, SEARCH_ATTRS);

    if (!searchResult.success || !searchResult.entries || searchResult.entries.length === 0) {
      logger.warn('LDAP user not found', { username, success: searchResult.success, entries: searchResult.entries?.length });
      throw new Error('Invalid credentials');
    }

    const userEntry = searchResult.entries[0];
    logger.info(userEntry)
    const userDN = userEntry.dn;
    logger.debug('LDAP user found, binding', { username, dn: userDN });

    const userClient = createLdapClient(config.ldap.url);
    const bindResult = await userClient.bind(userDN, password);
    userClient.unbind();

    if (!bindResult.success) {
      logger.warn('LDAP user bind failed', { username, dn: userDN, error: bindResult.error });
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
  } finally {
    client.unbind();
  }
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
