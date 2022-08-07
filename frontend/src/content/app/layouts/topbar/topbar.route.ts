import { Route } from '@angular/router';

import { TopbarComponent } from './topbar.component';

export const topbarRoute: Route = {
    path: '',
    component: TopbarComponent,
    outlet: 'topbar',
};
