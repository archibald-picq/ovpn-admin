
export class WirelessStatus {
  constructor(
    public readonly ap: string,
    public readonly essid: string,
    public readonly bitRate: number,
    public readonly frequency: number,
    public readonly quality: number,
  ) {
  }

  public static hydrate(obj: WirelessStatus): WirelessStatus {
    return new WirelessStatus(
      obj.ap,
      obj.essid,
      obj.bitRate,
      obj.frequency,
      obj.quality,
    )
  }
}

export class InterfaceRunning {
  constructor(
    public readonly name: string,
    public readonly mac: string,
    public readonly ips: string[],
    public readonly flags: string[],
    public readonly wireless: WirelessStatus|undefined,
  ) {
  }

  public static hydrate(obj: InterfaceRunning): InterfaceRunning {
    return new InterfaceRunning(
      obj.name,
      obj.mac,
      obj.ips,
      obj.flags,
      obj.wireless ? WirelessStatus.hydrate(obj.wireless) : undefined,
    );
  }
}
