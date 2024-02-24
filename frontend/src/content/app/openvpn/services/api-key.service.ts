import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {AppConfigService} from '../../shared/services/app-config.service';
import {ApiKey} from '../models/openvpn-config.model';
import {firstValueFrom} from 'rxjs';
import {ApiKeyEditDTO} from '../models/api-key-edit.model';

@Injectable()
export class ApiKeyService {
  public OPENVPN_ADMIN_API? = '';

  constructor(
    protected readonly http: HttpClient,
    protected readonly appConfigService: AppConfigService,
  ) {
    this.OPENVPN_ADMIN_API = appConfigService.get().openvpn?.url;
  }


  public async createApiKey(params: ApiKeyEditDTO): Promise<ApiKey> {
    return firstValueFrom(this.http.post<ApiKey>(this.OPENVPN_ADMIN_API+'/api/config/api-key/', params)).then(ApiKey.hydrate);
  }

  public async updateApiKey(id: string, params: ApiKeyEditDTO): Promise<ApiKey> {
    return firstValueFrom(this.http.put<ApiKey>(this.OPENVPN_ADMIN_API+'/api/config/api-key/'+id, params)).then(ApiKey.hydrate);
  }

  public async deleteApiKey(id: string): Promise<void> {
    return firstValueFrom(this.http.delete<void>(this.OPENVPN_ADMIN_API+'/api/config/api-key/'+id));
  }

}
