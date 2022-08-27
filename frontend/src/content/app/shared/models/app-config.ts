import { OpenvpnConfig } from '../../openvpn/models/openvpn-config.model';
import { ServiceConfig } from './service-config';


export class AppConfig {
  public color?: string;
  public user?: Record<string, any>;
  public openvpn?: OpenvpnConfig;
  public peripherals?: ServiceConfig;

  constructor(raw?: Record<string, any>) {
    if (raw) {
      this.import(raw);
    }
  }
  public static parse(raw: Record<string, any>): AppConfig {
    return new AppConfig(raw);
  }

  import(raw: Record<string, any>) {
    Object.assign(this, raw);
    if (raw.openvpn) {
      this.openvpn = OpenvpnConfig.parse(raw.openvpn);
    }
  }
}
