
export class UserProfile {
  public username?: string;
  public name?: string;
  public firstname?: string;
  public lastname?: string;

  constructor(raw: Record<string, any>) {
    Object.assign(this, raw);
    if (!this.name && (this.firstname || this.lastname)) {
      this.name = this.firstname + (this.firstname && this.lastname ? ' ' : '') + this.lastname;
    }
  }
  static parse(raw: Record<string, any>|undefined|null): UserProfile {
    return new UserProfile(raw ?? {});
  }
}
