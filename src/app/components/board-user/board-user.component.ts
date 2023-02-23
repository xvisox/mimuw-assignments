import {Component, OnInit} from '@angular/core';
import {OfferService} from "../../services/offer/offer.service";
import {RentedCar} from "./rented-car";
import {RentService} from "../../services/rent/rent.service";
import {StorageService} from "../../services/storage/storage.service";


@Component({
  selector: 'app-board-user',
  templateUrl: './board-user.component.html',
  styleUrls: ['./board-user.component.css']
})
export class BoardUserComponent implements OnInit {
  public NAN = "NaN";
  public content?: string;
  public error?: boolean;
  public extendPrice?: any;
  public days?: any;
  public cars: RentedCar[] = [];

  constructor(private offerService: OfferService, private rentalService: RentService, private storage: StorageService) {
  }

  ngOnInit(): void {
    this.offerService.getMyCars().subscribe({
      next: data => {
        this.content = "OK"
        this.cars = data;
        this.error = false;
      },
      error: err => {
        console.log(err)
        this.error = true;
        if (err.error) {
          this.content = JSON.parse(err.error).message;
        } else {
          this.content = "Error with status: " + err.status;
        }
      }
    });
  }

  setExtendPrice(days: any, price: number) {
    this.days = Number(days.value) + 1;
    this.extendPrice = this.days * price;
  }

  initExtendPrice() {
    this.extendPrice = this.NAN;
  }

  onExtend(carId: number) {
    this.rentalService.extendRental(this.storage.getUser().username, carId, this.days).subscribe({
      next: data => {
        console.log(data);
        this.reloadPage();
      },
      error: err => {
        console.log(err);
      }
    });
  }

  onReturn(carId: number) {
    this.rentalService.returnCar(this.storage.getUser().username, carId).subscribe({
      next: data => {
        console.log(data);
        this.reloadPage();
      },
      error: err => {
        console.log(err);
      }
    });
  }

  reloadPage(): void {
    window.location.reload();
  }
}
