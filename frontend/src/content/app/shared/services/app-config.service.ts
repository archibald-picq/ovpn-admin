import { Injectable } from '@angular/core';
import { AppConfig } from '../models/app-config';
import { HttpClient } from '@angular/common/http';

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
    Init(): Promise<any> {
        return this.httpClient.get(this.apiUrl+'/config')
            // .catch((err: HttpErrorResponse))
            .pipe(
                // map(user => console.warn('user', user))
            ).toPromise().then((ret) => {
                Object.assign(this.config, ret);
            }, (err) => {
                console.warn('err', err);
            });
    }
}
