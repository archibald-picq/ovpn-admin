import {Component, Input} from '@angular/core';
import {InterfaceRunning} from '../../models/node-interface.model';

@Component({
  selector: 'bus-net-interface',
  templateUrl: './net-interface.component.html',
  styleUrls: ['./net-interface.component.scss'],
})
export class NetInterfaceComponent {
  @Input()
  public interface?: InterfaceRunning;
}
