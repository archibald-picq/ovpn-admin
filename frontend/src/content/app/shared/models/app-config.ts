import { OpenvpnServiceConfig } from '../../openvpn/models/openvpn-config.model';
import { ServiceConfig } from './service-config';
import {UserProfile} from "./user-profile";


export class AppConfig {
  public color?: string;
  public user?: Record<string, any>;
  public openvpn?: OpenvpnServiceConfig;
  public peripherals?: ServiceConfig;

  import(raw: Record<string, any>) {
    if (raw.user) {
      this.user = UserProfile.parse(raw.user);
    }
    if (raw.openvpn) {
      if (!this.openvpn) {
        this.openvpn = OpenvpnServiceConfig.hydrate(raw.openvpn);
      } else {
        this.openvpn.import(raw.openvpn);
      }
    }
  }
}
