import { Injectable } from '@angular/core';
import { Router, NavigationError, RouterEvent } from '@angular/router';
import { Location } from '@angular/common';
import { filter } from 'rxjs/operators';

@Injectable()
export class RouterService {

    private errorRoute?: RouterEvent;

    constructor(
        private router: Router,
        private location: Location
    ) { }

    setRouteErrorHandler(): void {
        this.errorRoute = undefined;
        this.router.errorHandler = (error): void => {
            console.warn('errorHandler', error, 'go to router', this.errorRoute?.url);
            if (error.status === 403) {
                this.router.navigateByUrl('/denied', { skipLocationChange: true })
                    .then(() => this.location.go(this.errorRoute!.url));
            } else if (error.status === 503) {
                this.router.navigateByUrl('/fatal', { skipLocationChange: true })
                    .then(() => this.location.go(this.errorRoute!.url));
            }
        };

        this.router.events.pipe(
            filter(next => next instanceof NavigationError)
        ).subscribe((next) => {
            if (next instanceof RouterEvent) {
                this.errorRoute = next;
                console.warn('set last route to', this.errorRoute.url);
            }
        });
    }

    public getLastUrl(): string {
        return this.errorRoute!.url;
    }
}