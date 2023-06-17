
export class Hello {
  constructor(
    public readonly name: string,
    public readonly version: string,
    public readonly uptime: number,
    public readonly boot: Date,
    public readonly remote: string,
) {
  }

  public static hydrate(obj: Hello): Hello {
    return new Hello(
      obj.name,
      obj.version,
      obj.uptime,
      obj.boot ? new Date(obj.boot) : Hello.importDiffTime(obj.uptime),
      obj.remote,
    );
  }

  private static importDiffTime(diff: number): Date {
    const date = new Date();
    date.setMilliseconds(date.getMilliseconds() - diff);
    return date;
  }
}
