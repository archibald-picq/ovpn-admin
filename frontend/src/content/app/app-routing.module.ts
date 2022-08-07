import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';
import {DEBUG_INFO_ENABLED} from "./app.constants";
import { topbarRoute } from './layouts/topbar/topbar.route';

// import { errorRoute, navbarRoute } from './layouts';
// const LAYOUT_ROUTES = [navbarRoute, ...errorRoute];

@NgModule({
    imports: [
        RouterModule.forRoot(
            [
                {
                    path: '',
                    loadChildren: () => import('./openvpn/openvpn.module').then(m => m.OpenvpnModule)
                },
                {
                    path: '',
                    loadChildren: () => import('./error/error.module').then(m => m.ErrorModule)
                },
                topbarRoute,
            ],
            { enableTracing: DEBUG_INFO_ENABLED }
        ),
    ],
    exports: [RouterModule]
})
export class BusUiRoutingModule {}
