import { OpenvpnConfig } from '../../openvpn/models/openvpn-config.model';

export class ServiceConfig {
  public url?: string;
  public settings?: OpenvpnConfig;
}

export class AppConfig {
  public color?: string;
  public user?: Record<string, any>;
  public openvpn?: ServiceConfig;
  public peripherals?: ServiceConfig;

  constructor(raw?: Record<string, any>) {
    if (raw) {
      Object.assign(this, raw);
      if (raw.openvpn?.settings) {
        console.warn('import openvpn service config', raw.openvpn?.settings);
        this.openvpn!.settings = OpenvpnConfig.parse(raw.openvpn?.settings);
      }
    }
  }
  public static parse(raw: Record<string, any>): AppConfig {
    return new AppConfig(raw);
  }

  import(raw: Record<string, any>) {
    Object.assign(this, raw);
    if (raw.openvpn?.settings) {
      console.warn('import openvpn service config', raw.openvpn?.settings);
      this.openvpn!.settings = OpenvpnConfig.parse(raw.openvpn?.settings);
    }
  }
}
