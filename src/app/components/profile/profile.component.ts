import {Component, OnInit} from '@angular/core';
import {StorageService} from '../../services/storage/storage.service';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css']
})
export class ProfileComponent implements OnInit {
  public currentUser: any;
  public content = '';
  public status = '';
  public error = false;

  constructor(private storageService: StorageService) {
  }

  ngOnInit(): void {
    this.storageService.getUserProfile().subscribe({
      next: data => {
        this.content = "OK"
        this.currentUser = data.user;
        this.error = false;
        this.status = this.getStatusName(this.currentUser.moneySpent);
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

  getStatusName(moneySpent: number): string {
    if (moneySpent < 1000) {
      return "Bronze";
    } else if (moneySpent < 5000) {
      return "Silver";
    } else if (moneySpent < 10000) {
      return "Gold";
    }
    return "Platinum";
  }
}
