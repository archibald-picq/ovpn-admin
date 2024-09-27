import { Injectable } from '@angular/core';
import { AppConfig } from '../models/app-config';
import { HttpClient } from '@angular/common/http';
import {firstValueFrom} from 'rxjs';

@Injectable({providedIn: 'root'})
export class AppConfigService {
    private config: AppConfig = new AppConfig();
    private apiUrl = CONFIG_API_URL;

    constructor(
      private readonly httpClient: HttpClient,
    ) {
    }
    get(): AppConfig {
        return this.config;
    }
    init(): Promise<any> {
        return firstValueFrom(this.httpClient.get(this.apiUrl+'/config'))
          .then((ret: any) => {
              this.config.import(ret);
            }, (err) => {
                console.warn('err', err);
            });
    }

    reload(): Promise<any> {
      return this.init();
    }
}
