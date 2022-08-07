import { Route } from '@angular/router';
import { NotfoundPageComponent } from './notfound/notfound.component';
import { DeniedPageComponent } from './denied/denied.component';


export const NOTFOUND_ROUTES: Route[] = [{
    path: 'denied',
    component: DeniedPageComponent,
}, {
    path: 'fatal',
    component: DeniedPageComponent,
}, {
    path: '**',
    component: NotfoundPageComponent,
}];
