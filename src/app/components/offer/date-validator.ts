import {AbstractControl} from "@angular/forms";

export function DateValidator(control: AbstractControl): { [key: string]: boolean } | null {
  let from = control.get('startDate');
  let to = control.get('endDate');
  let c = new Date();
  if (new Date(from?.value) < c) {
    return {
      invalidFrom: true
    }
  }
  if (new Date(to?.value) < c) {
    return {
      invalidTo: true
    }
  }
  if (from?.value > to?.value) {
    return {
      dates: true
    };
  }
  return {};
}
