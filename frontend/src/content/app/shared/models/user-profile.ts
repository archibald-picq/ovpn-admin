
export class UserProfile {
    public username?: string;
    public firstname?: string;
    public lastname?: string;

    constructor(raw: Record<string, any>) {
        Object.assign(this, raw);
    }
    static parse(raw: Record<string, any>|undefined|null): UserProfile {
        return new UserProfile(raw ?? {});
    }
}