export interface IActiveDirectoryHelper {
    checkCredentials: (userPrincipalName: string, password: string) => Promise<ICredentialsResult>
    _getUserRole: (userPrincipalName: string, role: string) => Promise<string>
    getUserRoles: (userPrincipalName: string, roles: string[]) => Promise<string[]>
}

export interface IActiveDirectoryHelperConfig {
    url: string
    baseDN: string
    username: string
    password: string
}

export interface ICredentialsResult {
    kind: CheckCredentialsResultKind,
    userPrincipalName: string,
    reason?: FailedCheckCredentialsReason,
    reasonText?: string
}

export interface ISuccessfulCheckCredentialsResult {
    readonly kind: CheckCredentialsResultKind.SUCCESSFUL
    readonly login: string
}

export interface IFailedCheckCredentialsResult {
    readonly kind: CheckCredentialsResultKind.FAILED
    readonly login: string
    readonly reason: FailedCheckCredentialsReason
    readonly reasonText: string
}

export enum FailedCheckCredentialsReason {
    INVALID_USERNAME,
    INVALID_PASSWORD,
    USER_LOCKED,
    UNKNOWN_ERROR
}

export enum CheckCredentialsResultKind {
    SUCCESSFUL = 'SUCCESSFUL',
    FAILED = 'FAILED'
}

export type CheckCredentialsResult = ISuccessfulCheckCredentialsResult | IFailedCheckCredentialsResult
