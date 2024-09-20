import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {AppConfigService} from '../../shared/services/app-config.service';
import {User} from '../models/openvpn-config.model';
import {firstValueFrom} from 'rxjs';
import {AccountEditDTO} from '../models/account-edit.model';

@Injectable()
export class AccountService {
  public OPENVPN_ADMIN_API? = '';

  constructor(
    protected readonly http: HttpClient,
    protected readonly appConfigService: AppConfigService,
  ) {
    this.OPENVPN_ADMIN_API = appConfigService.get().openvpn?.url;
  }


  public async createAdminAccount(params: AccountEditDTO): Promise<void> {
    return firstValueFrom(this.http.post<void>(this.OPENVPN_ADMIN_API+'/api/config/admin/', params));
  }

  public async updateAdminAccount(username: string, params: Record<string, any>): Promise<void> {
    return firstValueFrom(this.http.put<void>(this.OPENVPN_ADMIN_API+'/api/config/admin/'+username, params));
  }

  public async deleteAdminAccount(user: User): Promise<void> {
    return firstValueFrom(this.http.delete<void>(this.OPENVPN_ADMIN_API+'/api/config/admin/'+user.username));
  }

}
