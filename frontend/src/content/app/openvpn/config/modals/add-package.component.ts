import {Component} from '@angular/core';
import {NgbActiveModal} from '@ng-bootstrap/ng-bootstrap';
import { PackageState } from '../../models/package-state.model';
import {PackageWanted} from '../../models/package-wanted.model';

@Component({
  selector: 'bus-add-package',
  templateUrl: './add-package.component.html',
  styleUrls: ['./add-package.component.scss'],
})
export class AddPackageComponent {
  public loading = false;
  public error = '';
  public name = '';
  public version?: string;

  constructor(
    public readonly modal: NgbActiveModal,
  ) {
  }

  public save(): void {
    this.modal.close(new PackageWanted(
      PackageState.INSTALLED,
      this.name,
      this.version,
    ));
  }
}
