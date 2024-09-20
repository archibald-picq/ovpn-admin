import {Route} from '@angular/router';
import {SetupComponent} from './setup.component';
import {CreateAccountComponent} from './steps/create-account.component';
import {JoinMasterComponent} from './steps/join-master.component';
import {ChooseRoleComponent} from './steps/choose-role.component';
import {CreateServerComponent} from './steps/create-server.component';

export const SETUP_ROUTES: Route[] = [{
  path: '',
  component: SetupComponent,
  children: [
    {
      path: '',
      component: ChooseRoleComponent,
    },
    {
      path: 'create-account',
      component: CreateAccountComponent,
    },
    {
      path: 'create-server',
      component: CreateServerComponent,
    },
    {
      path: 'join',
      component: JoinMasterComponent,
    },
  ],
}];
