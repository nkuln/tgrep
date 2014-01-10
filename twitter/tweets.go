package twitter

import(
)


type Tweets struct {
	Contributors []Contributors
	Coordinates Coordinates
	Created_at string
	User Users
	Text string
	Source string
	Lang string
}

type Contributors struct {
	Id int64
	Id_str string
	Screen_name string
}

type Coordinates struct {
	Coordinates []float64
	Type string
}

type Users struct {
	Contributors_enabled bool
	Created_at string
	Default_profile bool
	Defualt_profile_image bool
	Description string
	Favourites_count int
	Followers_count int
	Friends_count int
	Geo_enabled bool
	Id int64
	Name string
	Screen_name string
}
