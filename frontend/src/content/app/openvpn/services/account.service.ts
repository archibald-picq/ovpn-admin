import {Injectable} from '@angular/core';
import {HttpClient, HttpResponse} from '@angular/common/http';
import {AppConfigService} from '../../shared/services/app-config.service';
import {User} from '../models/openvpn-config.model';
import {firstValueFrom} from 'rxjs';
import {filter, map} from 'rxjs/operators';
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


  public async createAdminAccount(params: AccountEditDTO): Promise<User> {
    return firstValueFrom(this.http.post(this.OPENVPN_ADMIN_API+'/api/config/admin/', params, {
      observe: 'response',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
      map((response: HttpResponse<any>) => response.body),
    ));
  }

  public async updateAdminAccount(username: string, params: Record<string, any>): Promise<User> {
    return firstValueFrom(this.http.put(this.OPENVPN_ADMIN_API+'/api/config/admin/'+username, params, {
      observe: 'response',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
      map((response: HttpResponse<any>) => response.body),
    ));
  }

  public async deleteAdminAccount(user: User): Promise<any> {
    return firstValueFrom(this.http.delete(this.OPENVPN_ADMIN_API+'/api/config/admin/'+user.username, {
      observe: 'response',
    }).pipe(
      filter((response: HttpResponse<any>) => response.ok),
      map(() => undefined as any)
    ));
  }

}
