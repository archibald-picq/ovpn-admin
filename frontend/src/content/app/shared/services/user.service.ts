import { HttpClient, HttpResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { filter, map } from 'rxjs/operators';
import { UserProfile } from '../models/user-profile';
import { OperatorFunction } from 'rxjs';
import { AppConfigService } from './app-config.service';
import { AppConfig } from '../models/app-config';

@Injectable({ providedIn: 'root' })
export class UserService {
    private appConfig: AppConfig;
    private apiUrl = CONFIG_API_URL;

    constructor(
        private http: HttpClient,
        private appConfigService: AppConfigService,
    ) {
        this.appConfig = appConfigService.get();
    }
    public async authenticate(username: string, password: string): Promise<UserProfile> {
        const body = {
            username,
            password,
        }

        return await this.http.post<UserProfile>(`${this.apiUrl}/authenticate`, body, {
            observe: 'response'
        }).pipe(
            filter((response: HttpResponse<UserProfile>) => response.ok),
            map((res: HttpResponse<UserProfile>) => this.authenticated(res.body ?? {})),
            filter(x => x !== null) as OperatorFunction<UserProfile | undefined, UserProfile>
        ).toPromise() as Promise<UserProfile>;
    }

    private authenticated(body: UserProfile): UserProfile {
        const userData = UserProfile.parse(body);
        this.appConfig.user = userData;
        return userData;
    }

    public async logout(): Promise<void> {
        return this.http.post<UserProfile>(`${this.apiUrl}/logout`, {}, {
            observe: 'response'
        }).pipe(
            map(() => {
                this.loggedOut();
                console.warn('logued out');
                return;
            })
        ).toPromise();
    }

    private loggedOut(): void {
        this.appConfig.user = undefined;
    }
}
