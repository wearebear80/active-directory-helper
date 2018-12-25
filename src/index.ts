import * as ActiveDirectory from 'activedirectory'
import * as types from './interfaces'
import ldapEscape from 'ldap-escape'
import { getLogger } from 'log4js'

const logger = getLogger('LdapЕбала')

// @TODO types
const groupSearchQuery = (group: string, userPrincipalName: string) =>
  ldapEscape.filter`(&(userPrincipalName=${userPrincipalName})(memberof=CN=${group}))`

export class ActiveDirectoryHelper implements types.IActiveDirectoryHelper {
    readonly ad: any

    constructor(
        config: types.IActiveDirectoryHelperConfig
    ) {
        this.ad = new ActiveDirectory(config)
    }

    async checkCredentials(userPrincipalName: string, password: string): Promise<types.ICredentialsResult> {
        return new Promise((resolve: (result: any) => any, reject: any) => {
            this.ad.authenticate(userPrincipalName, password, (err: any, result: any) => {
                if (err) {
                    logger.error(`Authentication for user ${userPrincipalName}: ${err}`)
                    resolve({
                        kind: types.CheckCredentialsResultKind.FAILED,
                        userPrincipalName,
                        reason: types.FailedCheckCredentialsReason.UNKNOWN_ERROR,
                        reasonText: err
                    })
                }

                if (!result) {
                    logger.info(`User principal name ${userPrincipalName} is not authenticated: invalid login or password`)
                    resolve({
                        kind: types.CheckCredentialsResultKind.FAILED,
                        userPrincipalName,
                        reason: types.FailedCheckCredentialsReason.INVALID_PASSWORD,
                        reasonText: 'Unauthenticated'
                    })
                }

                logger.info(`User ${userPrincipalName} authenticated successfully`)
                return resolve({
                    kind: types.CheckCredentialsResultKind.SUCCESSFUL,
                    userPrincipalName
                })
            })
        })
    }

    async _getUserRole(userPrincipalName: string, role: string): Promise<string> {
        return new Promise((resolve: (result: string) => void, reject: any) => {
                this.ad.find(groupSearchQuery(role, userPrincipalName), function(err: any, results: any) {
                    logger.info(`getUserRole ${role}`)
                    if (err) {
                        logger.error(`getUserRole ${role} failed`)
                        reject(err)
                    }
                    const userHasRole = results && results.users && results.users.length === 1
                    if (userHasRole) {
                        resolve(role)
                    }
                    resolve('')
                })
        })
    }

    async getUserRoles(userPrincipalName: string, roles: string[]): Promise<string[]> {
        const result = []
        logger.info(`get user roles for ${userPrincipalName}`)
        for (let i in roles) {
            if (roles.hasOwnProperty(i)) {
                const role: string = await this._getUserRole(userPrincipalName, roles[i])
                if (role) {
                    result.push(role)
                }
            }
        }
        return result
    }
}
