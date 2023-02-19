import {Component, OnInit} from '@angular/core';
import {Car} from "./car";
import {OfferService} from "../../services/offer/offer.service";
import {HttpErrorResponse} from "@angular/common/http";

@Component({
  selector: 'app-offer',
  templateUrl: './offer.component.html',
  styleUrls: ['./offer.component.css']
})
export class OfferComponent implements OnInit {
  public cars: Car[] = [];
  public content?: any;

  constructor(private offerService: OfferService) {
  }

  ngOnInit(): void {
    this.offerService.getCars().subscribe({
      next: data => {
        this.content = "OK"
        this.cars = data;
      },
      error: err => {
        console.log(err)
        if (err.error) {
          this.content = err.error.message;
        } else {
          this.content = "Error with status: " + err.status;
        }
      }
    });
  }
}
