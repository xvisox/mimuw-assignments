import {Component, OnInit} from '@angular/core';
import {Car} from "./car";
import {OfferService} from "../../services/offer/offer.service";
import {StorageService} from "../../services/storage/storage.service";
import {RentService} from "../../services/rent/rent.service";
import {FormControl, FormGroup, Validators} from "@angular/forms";
import {DateValidator} from "./date-validator";

@Component({
  selector: 'app-offer',
  templateUrl: './offer.component.html',
  styleUrls: ['./offer.component.css']
})
export class OfferComponent implements OnInit {
  public cars: Car[] = [];
  public content?: any;
  public error?: boolean;
  public logged?: boolean;
  public form: FormGroup = new FormGroup({
    carId: new FormControl(-1),
    startDate: new FormControl('', [Validators.required]),
    endDate: new FormControl('', [Validators.required])
  }, {validators: DateValidator});

  constructor(private offerService: OfferService, private storageService: StorageService,
              private rentService: RentService) {
  }

  ngOnInit(): void {
    this.logged = this.storageService.isLoggedIn();
    this.offerService.getCars().subscribe({
      next: data => {
        this.content = "OK"
        this.cars = data;
        this.error = false;
      },
      error: err => {
        console.log(err)
        this.error = true;
        if (err.error) {
          this.content = err.error.message;
        } else {
          this.content = "Error with status: " + err.status;
        }
      }
    });
  }

  get f() {
    return this.form.controls;
  }

  get endDate() {
    return this.form.get('endDate');
  }

  get startDate() {
    return this.form.get('startDate');
  }

  get carId() {
    return this.form.get('carId');
  }

  onSubmit(): void {
    const carId = this.form.get('carId');
    const startDate = this.form.get('startDate');
    const endDate = this.form.get('endDate');
    console.log(carId, startDate, endDate);
    this.rentService.rentCar(this.storageService.getUser().username, carId?.value, startDate?.value, endDate?.value)
      .subscribe({
        next: data => {
          console.log(data);
        },
        error: err => {
          console.log(err);
        }
      });
    this.reloadPage();
  }

  initForm(id: number): void {
    this.form = new FormGroup({
      carId: new FormControl(id),
      startDate: new FormControl('', [Validators.required]),
      endDate: new FormControl('', [Validators.required])
    }, {validators: DateValidator});
  }

  reloadPage(): void {
    window.location.reload();
  }

  calculatePrice(price: number) {
    const startDate = this.form.get('startDate');
    const endDate = this.form.get('endDate');
    let date = new Date(startDate?.value);
    let currentDate = new Date(endDate?.value);

    return Math.floor((currentDate.getTime() - date.getTime()) / 1000 / 60 / 60 / 24) * price;
  }
}
