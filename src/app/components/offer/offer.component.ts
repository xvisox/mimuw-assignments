import {Component, OnInit} from '@angular/core';
import {Car} from "./car";
import {OfferService} from "../../services/offer/offer.service";
import {HttpErrorResponse} from "@angular/common/http";
import {StorageService} from "../../services/storage/storage.service";
import {RentService} from "../../services/rent/rent.service";

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
  form: any = {
    carId: null,
    startDate: null,
    endDate: null,
  };

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

  onSubmit(): void {
    const {carId, startDate, endDate} = this.form;
    this.rentService.rentCar(this.storageService.getUser().username, carId, startDate, endDate).subscribe({
      next: data => {
        console.log(data);
      },
      error: err => {
        console.log(err);
      }
    });
  }
}
