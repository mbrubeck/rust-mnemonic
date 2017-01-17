//! This is a Rust port of the mnemonic encoder originally written in C by Oren
//! Tirosh and available from:
//!
//! https://github.com/singpolyma/mnemonicode
//!
//! These routines implement a method for encoding binary data into a sequence
//! of words which can be spoken over the phone, for example, and converted
//! back to data on the other side.
//!
//! For more information, see:
//!
//! http://web.archive.org/web/20101031205747/http://www.tothink.com/mnemonic/
//!
//! ## Example
//!
//! ```rust
//! let bytes = [101, 2, 240, 6, 108, 11, 20, 97];
//!
//! let s = mnemonic::to_string(&bytes);
//! assert_eq!(s, "digital-apollo-aroma--rival-artist-rebel");
//!
//! let mut decoded = Vec::<u8>::new();
//! mnemonic::decode(s, &mut decoded).unwrap();
//!
//! assert_eq!(decoded, [101, 2, 240, 6, 108, 11, 20, 97]);
//! ```

extern crate byteorder;
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use std::collections::HashMap;
use std::error::Error as ErrorTrait;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::result;

/// Errors returned by mnemonic decoding.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    UnrecognizedWord,
    UnexpectedRemainder,
    UnexpectedRemainderWord,
    DataPastRemainder,
    InvalidEncoding,
}
use Error::*;

/// Result type returned by mnemonic decoding.
pub type Result<T> = result::Result<T, Error>;

impl From<io::Error> for Error {
    fn from(other: io::Error) -> Self { Io(other) }
}

impl ErrorTrait for Error {
    fn description(&self) -> &str {
        match *self {
            Io(ref e) => e.description(),
            UnrecognizedWord => "Unrecognized word",
            UnexpectedRemainder => "Unexpected remainder (possible truncated string)",
            UnexpectedRemainderWord => "Unexpected 24-bit remainder word",
            DataPastRemainder => "Unexpected data past 24-bit remainder",
            InvalidEncoding => "Invalid encoding",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// cubic root of 2^32, rounded up
const MN_BASE: u32 = 1626;

/// Number of extra words for 24 bit remainders
const MN_REMAINDER: usize = 7;

/// Default format for encoding
pub const MN_FDEFAULT: &'static [u8] = b"x-x-x--";

static MN_WORDS: [&'static [u8]; MN_BASE as usize + MN_REMAINDER] = [
    b"academy",  b"acrobat",  b"active",   b"actor",    b"adam",     b"admiral",
    b"adrian",   b"africa",   b"agenda",   b"agent",    b"airline",  b"airport",
    b"aladdin",  b"alarm",    b"alaska",   b"albert",   b"albino",   b"album",
    b"alcohol",  b"alex",     b"algebra",  b"alibi",    b"alice",    b"alien",
    b"alpha",    b"alpine",   b"amadeus",  b"amanda",   b"amazon",   b"amber",
    b"america",  b"amigo",    b"analog",   b"anatomy",  b"angel",    b"animal",
    b"antenna",  b"antonio",  b"apollo",   b"april",    b"archive",  b"arctic",
    b"arizona",  b"arnold",   b"aroma",    b"arthur",   b"artist",   b"asia",
    b"aspect",   b"aspirin",  b"athena",   b"athlete",  b"atlas",    b"audio",
    b"august",   b"austria",  b"axiom",    b"aztec",    b"balance",  b"ballad",
    b"banana",   b"bandit",   b"banjo",    b"barcode",  b"baron",    b"basic",
    b"battery",  b"belgium",  b"berlin",   b"bermuda",  b"bernard",  b"bikini",
    b"binary",   b"bingo",    b"biology",  b"block",    b"blonde",   b"bonus",
    b"boris",    b"boston",   b"boxer",    b"brandy",   b"bravo",    b"brazil",
    b"bronze",   b"brown",    b"bruce",    b"bruno",    b"burger",   b"burma",
    b"cabinet",  b"cactus",   b"cafe",     b"cairo",    b"cake",     b"calypso",
    b"camel",    b"camera",   b"campus",   b"canada",   b"canal",    b"cannon",
    b"canoe",    b"cantina",  b"canvas",   b"canyon",   b"capital",  b"caramel",
    b"caravan",  b"carbon",   b"cargo",    b"carlo",    b"carol",    b"carpet",
    b"cartel",   b"casino",   b"castle",   b"castro",   b"catalog",  b"caviar",
    b"cecilia",  b"cement",   b"center",   b"century",  b"ceramic",  b"chamber",
    b"chance",   b"change",   b"chaos",    b"charlie",  b"charm",    b"charter",
    b"chef",     b"chemist",  b"cherry",   b"chess",    b"chicago",  b"chicken",
    b"chief",    b"china",    b"cigar",    b"cinema",   b"circus",   b"citizen",
    b"city",     b"clara",    b"classic",  b"claudia",  b"clean",    b"client",
    b"climax",   b"clinic",   b"clock",    b"club",     b"cobra",    b"coconut",
    b"cola",     b"collect",  b"colombo",  b"colony",   b"color",    b"combat",
    b"comedy",   b"comet",    b"command",  b"compact",  b"company",  b"complex",
    b"concept",  b"concert",  b"connect",  b"consul",   b"contact",  b"context",
    b"contour",  b"control",  b"convert",  b"copy",     b"corner",   b"corona",
    b"correct",  b"cosmos",   b"couple",   b"courage",  b"cowboy",   b"craft",
    b"crash",    b"credit",   b"cricket",  b"critic",   b"crown",    b"crystal",
    b"cuba",     b"culture",  b"dallas",   b"dance",    b"daniel",   b"david",
    b"decade",   b"decimal",  b"deliver",  b"delta",    b"deluxe",   b"demand",
    b"demo",     b"denmark",  b"derby",    b"design",   b"detect",   b"develop",
    b"diagram",  b"dialog",   b"diamond",  b"diana",    b"diego",    b"diesel",
    b"diet",     b"digital",  b"dilemma",  b"diploma",  b"direct",   b"disco",
    b"disney",   b"distant",  b"doctor",   b"dollar",   b"dominic",  b"domino",
    b"donald",   b"dragon",   b"drama",    b"dublin",   b"duet",     b"dynamic",
    b"east",     b"ecology",  b"economy",  b"edgar",    b"egypt",    b"elastic",
    b"elegant",  b"element",  b"elite",    b"elvis",    b"email",    b"energy",
    b"engine",   b"english",  b"episode",  b"equator",  b"escort",   b"ethnic",
    b"europe",   b"everest",  b"evident",  b"exact",    b"example",  b"exit",
    b"exotic",   b"export",   b"express",  b"extra",    b"fabric",   b"factor",
    b"falcon",   b"family",   b"fantasy",  b"fashion",  b"fiber",    b"fiction",
    b"fidel",    b"fiesta",   b"figure",   b"film",     b"filter",   b"final",
    b"finance",  b"finish",   b"finland",  b"flash",    b"florida",  b"flower",
    b"fluid",    b"flute",    b"focus",    b"ford",     b"forest",   b"formal",
    b"format",   b"formula",  b"fortune",  b"forum",    b"fragile",  b"france",
    b"frank",    b"friend",   b"frozen",   b"future",   b"gabriel",  b"galaxy",
    b"gallery",  b"gamma",    b"garage",   b"garden",   b"garlic",   b"gemini",
    b"general",  b"genetic",  b"genius",   b"germany",  b"global",   b"gloria",
    b"golf",     b"gondola",  b"gong",     b"good",     b"gordon",   b"gorilla",
    b"grand",    b"granite",  b"graph",    b"green",    b"group",    b"guide",
    b"guitar",   b"guru",     b"hand",     b"happy",    b"harbor",   b"harmony",
    b"harvard",  b"havana",   b"hawaii",   b"helena",   b"hello",    b"henry",
    b"hilton",   b"history",  b"horizon",  b"hotel",    b"human",    b"humor",
    b"icon",     b"idea",     b"igloo",    b"igor",     b"image",    b"impact",
    b"import",   b"index",    b"india",    b"indigo",   b"input",    b"insect",
    b"instant",  b"iris",     b"italian",  b"jacket",   b"jacob",    b"jaguar",
    b"janet",    b"japan",    b"jargon",   b"jazz",     b"jeep",     b"john",
    b"joker",    b"jordan",   b"jumbo",    b"june",     b"jungle",   b"junior",
    b"jupiter",  b"karate",   b"karma",    b"kayak",    b"kermit",   b"kilo",
    b"king",     b"koala",    b"korea",    b"labor",    b"lady",     b"lagoon",
    b"laptop",   b"laser",    b"latin",    b"lava",     b"lecture",  b"left",
    b"legal",    b"lemon",    b"level",    b"lexicon",  b"liberal",  b"libra",
    b"limbo",    b"limit",    b"linda",    b"linear",   b"lion",     b"liquid",
    b"liter",    b"little",   b"llama",    b"lobby",    b"lobster",  b"local",
    b"logic",    b"logo",     b"lola",     b"london",   b"lotus",    b"lucas",
    b"lunar",    b"machine",  b"macro",    b"madam",    b"madonna",  b"madrid",
    b"maestro",  b"magic",    b"magnet",   b"magnum",   b"major",    b"mama",
    b"mambo",    b"manager",  b"mango",    b"manila",   b"marco",    b"marina",
    b"market",   b"mars",     b"martin",   b"marvin",   b"master",   b"matrix",
    b"maximum",  b"media",    b"medical",  b"mega",     b"melody",   b"melon",
    b"memo",     b"mental",   b"mentor",   b"menu",     b"mercury",  b"message",
    b"metal",    b"meteor",   b"meter",    b"method",   b"metro",    b"mexico",
    b"miami",    b"micro",    b"million",  b"mineral",  b"minimum",  b"minus",
    b"minute",   b"miracle",  b"mirage",   b"miranda",  b"mister",   b"mixer",
    b"mobile",   b"model",    b"modem",    b"modern",   b"modular",  b"moment",
    b"monaco",   b"monica",   b"monitor",  b"mono",     b"monster",  b"montana",
    b"morgan",   b"motel",    b"motif",    b"motor",    b"mozart",   b"multi",
    b"museum",   b"music",    b"mustang",  b"natural",  b"neon",     b"nepal",
    b"neptune",  b"nerve",    b"neutral",  b"nevada",   b"news",     b"ninja",
    b"nirvana",  b"normal",   b"nova",     b"novel",    b"nuclear",  b"numeric",
    b"nylon",    b"oasis",    b"object",   b"observe",  b"ocean",    b"octopus",
    b"olivia",   b"olympic",  b"omega",    b"opera",    b"optic",    b"optimal",
    b"orange",   b"orbit",    b"organic",  b"orient",   b"origin",   b"orlando",
    b"oscar",    b"oxford",   b"oxygen",   b"ozone",    b"pablo",    b"pacific",
    b"pagoda",   b"palace",   b"pamela",   b"panama",   b"panda",    b"panel",
    b"panic",    b"paradox",  b"pardon",   b"paris",    b"parker",   b"parking",
    b"parody",   b"partner",  b"passage",  b"passive",  b"pasta",    b"pastel",
    b"patent",   b"patriot",  b"patrol",   b"patron",   b"pegasus",  b"pelican",
    b"penguin",  b"pepper",   b"percent",  b"perfect",  b"perfume",  b"period",
    b"permit",   b"person",   b"peru",     b"phone",    b"photo",    b"piano",
    b"picasso",  b"picnic",   b"picture",  b"pigment",  b"pilgrim",  b"pilot",
    b"pirate",   b"pixel",    b"pizza",    b"planet",   b"plasma",   b"plaster",
    b"plastic",  b"plaza",    b"pocket",   b"poem",     b"poetic",   b"poker",
    b"polaris",  b"police",   b"politic",  b"polo",     b"polygon",  b"pony",
    b"popcorn",  b"popular",  b"postage",  b"postal",   b"precise",  b"prefix",
    b"premium",  b"present",  b"price",    b"prince",   b"printer",  b"prism",
    b"private",  b"product",  b"profile",  b"program",  b"project",  b"protect",
    b"proton",   b"public",   b"pulse",    b"puma",     b"pyramid",  b"queen",
    b"radar",    b"radio",    b"random",   b"rapid",    b"rebel",    b"record",
    b"recycle",  b"reflex",   b"reform",   b"regard",   b"regular",  b"relax",
    b"report",   b"reptile",  b"reverse",  b"ricardo",  b"ringo",    b"ritual",
    b"robert",   b"robot",    b"rocket",   b"rodeo",    b"romeo",    b"royal",
    b"russian",  b"safari",   b"salad",    b"salami",   b"salmon",   b"salon",
    b"salute",   b"samba",    b"sandra",   b"santana",  b"sardine",  b"school",
    b"screen",   b"script",   b"second",   b"secret",   b"section",  b"segment",
    b"select",   b"seminar",  b"senator",  b"senior",   b"sensor",   b"serial",
    b"service",  b"sheriff",  b"shock",    b"sierra",   b"signal",   b"silicon",
    b"silver",   b"similar",  b"simon",    b"single",   b"siren",    b"slogan",
    b"social",   b"soda",     b"solar",    b"solid",    b"solo",     b"sonic",
    b"soviet",   b"special",  b"speed",    b"spiral",   b"spirit",   b"sport",
    b"static",   b"station",  b"status",   b"stereo",   b"stone",    b"stop",
    b"street",   b"strong",   b"student",  b"studio",   b"style",    b"subject",
    b"sultan",   b"super",    b"susan",    b"sushi",    b"suzuki",   b"switch",
    b"symbol",   b"system",   b"tactic",   b"tahiti",   b"talent",   b"tango",
    b"tarzan",   b"taxi",     b"telex",    b"tempo",    b"tennis",   b"texas",
    b"textile",  b"theory",   b"thermos",  b"tiger",    b"titanic",  b"tokyo",
    b"tomato",   b"topic",    b"tornado",  b"toronto",  b"torpedo",  b"total",
    b"totem",    b"tourist",  b"tractor",  b"traffic",  b"transit",  b"trapeze",
    b"travel",   b"tribal",   b"trick",    b"trident",  b"trilogy",  b"tripod",
    b"tropic",   b"trumpet",  b"tulip",    b"tuna",     b"turbo",    b"twist",
    b"ultra",    b"uniform",  b"union",    b"uranium",  b"vacuum",   b"valid",
    b"vampire",  b"vanilla",  b"vatican",  b"velvet",   b"ventura",  b"venus",
    b"vertigo",  b"veteran",  b"victor",   b"video",    b"vienna",   b"viking",
    b"village",  b"vincent",  b"violet",   b"violin",   b"virtual",  b"virus",
    b"visa",     b"vision",   b"visitor",  b"visual",   b"vitamin",  b"viva",
    b"vocal",    b"vodka",    b"volcano",  b"voltage",  b"volume",   b"voyage",
    b"water",    b"weekend",  b"welcome",  b"western",  b"window",   b"winter",
    b"wizard",   b"wolf",     b"world",    b"xray",     b"yankee",   b"yoga",
    b"yogurt",   b"yoyo",     b"zebra",    b"zero",     b"zigzag",   b"zipper",
    b"zodiac",   b"zoom",     b"abraham",  b"action",   b"address",  b"alabama",
    b"alfred",   b"almond",   b"ammonia",  b"analyze",  b"annual",   b"answer",
    b"apple",    b"arena",    b"armada",   b"arsenal",  b"atlanta",  b"atomic",
    b"avenue",   b"average",  b"bagel",    b"baker",    b"ballet",   b"bambino",
    b"bamboo",   b"barbara",  b"basket",   b"bazaar",   b"benefit",  b"bicycle",
    b"bishop",   b"blitz",    b"bonjour",  b"bottle",   b"bridge",   b"british",
    b"brother",  b"brush",    b"budget",   b"cabaret",  b"cadet",    b"candle",
    b"capitan",  b"capsule",  b"career",   b"cartoon",  b"channel",  b"chapter",
    b"cheese",   b"circle",   b"cobalt",   b"cockpit",  b"college",  b"compass",
    b"comrade",  b"condor",   b"crimson",  b"cyclone",  b"darwin",   b"declare",
    b"degree",   b"delete",   b"delphi",   b"denver",   b"desert",   b"divide",
    b"dolby",    b"domain",   b"domingo",  b"double",   b"drink",    b"driver",
    b"eagle",    b"earth",    b"echo",     b"eclipse",  b"editor",   b"educate",
    b"edward",   b"effect",   b"electra",  b"emerald",  b"emotion",  b"empire",
    b"empty",    b"escape",   b"eternal",  b"evening",  b"exhibit",  b"expand",
    b"explore",  b"extreme",  b"ferrari",  b"first",    b"flag",     b"folio",
    b"forget",   b"forward",  b"freedom",  b"fresh",    b"friday",   b"fuji",
    b"galileo",  b"garcia",   b"genesis",  b"gold",     b"gravity",  b"habitat",
    b"hamlet",   b"harlem",   b"helium",   b"holiday",  b"house",    b"hunter",
    b"ibiza",    b"iceberg",  b"imagine",  b"infant",   b"isotope",  b"jackson",
    b"jamaica",  b"jasmine",  b"java",     b"jessica",  b"judo",     b"kitchen",
    b"lazarus",  b"letter",   b"license",  b"lithium",  b"loyal",    b"lucky",
    b"magenta",  b"mailbox",  b"manual",   b"marble",   b"mary",     b"maxwell",
    b"mayor",    b"milk",     b"monarch",  b"monday",   b"money",    b"morning",
    b"mother",   b"mystery",  b"native",   b"nectar",   b"nelson",   b"network",
    b"next",     b"nikita",   b"nobel",    b"nobody",   b"nominal",  b"norway",
    b"nothing",  b"number",   b"october",  b"office",   b"oliver",   b"opinion",
    b"option",   b"order",    b"outside",  b"package",  b"pancake",  b"pandora",
    b"panther",  b"papa",     b"patient",  b"pattern",  b"pedro",    b"pencil",
    b"people",   b"phantom",  b"philips",  b"pioneer",  b"pluto",    b"podium",
    b"portal",   b"potato",   b"prize",    b"process",  b"protein",  b"proxy",
    b"pump",     b"pupil",    b"python",   b"quality",  b"quarter",  b"quiet",
    b"rabbit",   b"radical",  b"radius",   b"rainbow",  b"ralph",    b"ramirez",
    b"ravioli",  b"raymond",  b"respect",  b"respond",  b"result",   b"resume",
    b"retro",    b"richard",  b"right",    b"risk",     b"river",    b"roger",
    b"roman",    b"rondo",    b"sabrina",  b"salary",   b"salsa",    b"sample",
    b"samuel",   b"saturn",   b"savage",   b"scarlet",  b"scoop",    b"scorpio",
    b"scratch",  b"scroll",   b"sector",   b"serpent",  b"shadow",   b"shampoo",
    b"sharon",   b"sharp",    b"short",    b"shrink",   b"silence",  b"silk",
    b"simple",   b"slang",    b"smart",    b"smoke",    b"snake",    b"society",
    b"sonar",    b"sonata",   b"soprano",  b"source",   b"sparta",   b"sphere",
    b"spider",   b"sponsor",  b"spring",   b"acid",     b"adios",    b"agatha",
    b"alamo",    b"alert",    b"almanac",  b"aloha",    b"andrea",   b"anita",
    b"arcade",   b"aurora",   b"avalon",   b"baby",     b"baggage",  b"balloon",
    b"bank",     b"basil",    b"begin",    b"biscuit",  b"blue",     b"bombay",
    b"brain",    b"brenda",   b"brigade",  b"cable",    b"carmen",   b"cello",
    b"celtic",   b"chariot",  b"chrome",   b"citrus",   b"civil",    b"cloud",
    b"common",   b"compare",  b"cool",     b"copper",   b"coral",    b"crater",
    b"cubic",    b"cupid",    b"cycle",    b"depend",   b"door",     b"dream",
    b"dynasty",  b"edison",   b"edition",  b"enigma",   b"equal",    b"eric",
    b"event",    b"evita",    b"exodus",   b"extend",   b"famous",   b"farmer",
    b"food",     b"fossil",   b"frog",     b"fruit",    b"geneva",   b"gentle",
    b"george",   b"giant",    b"gilbert",  b"gossip",   b"gram",     b"greek",
    b"grille",   b"hammer",   b"harvest",  b"hazard",   b"heaven",   b"herbert",
    b"heroic",   b"hexagon",  b"husband",  b"immune",   b"inca",     b"inch",
    b"initial",  b"isabel",   b"ivory",    b"jason",    b"jerome",   b"joel",
    b"joshua",   b"journal",  b"judge",    b"juliet",   b"jump",     b"justice",
    b"kimono",   b"kinetic",  b"leonid",   b"lima",     b"maze",     b"medusa",
    b"member",   b"memphis",  b"michael",  b"miguel",   b"milan",    b"mile",
    b"miller",   b"mimic",    b"mimosa",   b"mission",  b"monkey",   b"moral",
    b"moses",    b"mouse",    b"nancy",    b"natasha",  b"nebula",   b"nickel",
    b"nina",     b"noise",    b"orchid",   b"oregano",  b"origami",  b"orinoco",
    b"orion",    b"othello",  b"paper",    b"paprika",  b"prelude",  b"prepare",
    b"pretend",  b"profit",   b"promise",  b"provide",  b"puzzle",   b"remote",
    b"repair",   b"reply",    b"rival",    b"riviera",  b"robin",    b"rose",
    b"rover",    b"rudolf",   b"saga",     b"sahara",   b"scholar",  b"shelter",
    b"ship",     b"shoe",     b"sigma",    b"sister",   b"sleep",    b"smile",
    b"spain",    b"spark",    b"split",    b"spray",    b"square",   b"stadium",
    b"star",     b"storm",    b"story",    b"strange",  b"stretch",  b"stuart",
    b"subway",   b"sugar",    b"sulfur",   b"summer",   b"survive",  b"sweet",
    b"swim",     b"table",    b"taboo",    b"target",   b"teacher",  b"telecom",
    b"temple",   b"tibet",    b"ticket",   b"tina",     b"today",    b"toga",
    b"tommy",    b"tower",    b"trivial",  b"tunnel",   b"turtle",   b"twin",
    b"uncle",    b"unicorn",  b"unique",   b"update",   b"valery",   b"vega",
    b"version",  b"voodoo",   b"warning",  b"william",  b"wonder",   b"year",
    b"yellow",   b"young",    b"absent",   b"absorb",   b"accent",   b"alfonso",
    b"alias",    b"ambient",  b"andy",     b"anvil",    b"appear",   b"apropos",
    b"archer",   b"ariel",    b"armor",    b"arrow",    b"austin",   b"avatar",
    b"axis",     b"baboon",   b"bahama",   b"bali",     b"balsa",    b"bazooka",
    b"beach",    b"beast",    b"beatles",  b"beauty",   b"before",   b"benny",
    b"betty",    b"between",  b"beyond",   b"billy",    b"bison",    b"blast",
    b"bless",    b"bogart",   b"bonanza",  b"book",     b"border",   b"brave",
    b"bread",    b"break",    b"broken",   b"bucket",   b"buenos",   b"buffalo",
    b"bundle",   b"button",   b"buzzer",   b"byte",     b"caesar",   b"camilla",
    b"canary",   b"candid",   b"carrot",   b"cave",     b"chant",    b"child",
    b"choice",   b"chris",    b"cipher",   b"clarion",  b"clark",    b"clever",
    b"cliff",    b"clone",    b"conan",    b"conduct",  b"congo",    b"content",
    b"costume",  b"cotton",   b"cover",    b"crack",    b"current",  b"danube",
    b"data",     b"decide",   b"desire",   b"detail",   b"dexter",   b"dinner",
    b"dispute",  b"donor",    b"druid",    b"drum",     b"easy",     b"eddie",
    b"enjoy",    b"enrico",   b"epoxy",    b"erosion",  b"except",   b"exile",
    b"explain",  b"fame",     b"fast",     b"father",   b"felix",    b"field",
    b"fiona",    b"fire",     b"fish",     b"flame",    b"flex",     b"flipper",
    b"float",    b"flood",    b"floor",    b"forbid",   b"forever",  b"fractal",
    b"frame",    b"freddie",  b"front",    b"fuel",     b"gallop",   b"game",
    b"garbo",    b"gate",     b"gibson",   b"ginger",   b"giraffe",  b"gizmo",
    b"glass",    b"goblin",   b"gopher",   b"grace",    b"gray",     b"gregory",
    b"grid",     b"griffin",  b"ground",   b"guest",    b"gustav",   b"gyro",
    b"hair",     b"halt",     b"harris",   b"heart",    b"heavy",    b"herman",
    b"hippie",   b"hobby",    b"honey",    b"hope",     b"horse",    b"hostel",
    b"hydro",    b"imitate",  b"info",     b"ingrid",   b"inside",   b"invent",
    b"invest",   b"invite",   b"iron",     b"ivan",     b"james",    b"jester",
    b"jimmy",    b"join",     b"joseph",   b"juice",    b"julius",   b"july",
    b"justin",   b"kansas",   b"karl",     b"kevin",    b"kiwi",     b"ladder",
    b"lake",     b"laura",    b"learn",    b"legacy",   b"legend",   b"lesson",
    b"life",     b"light",    b"list",     b"locate",   b"lopez",    b"lorenzo",
    b"love",     b"lunch",    b"malta",    b"mammal",   b"margo",    b"marion",
    b"mask",     b"match",    b"mayday",   b"meaning",  b"mercy",    b"middle",
    b"mike",     b"mirror",   b"modest",   b"morph",    b"morris",   b"nadia",
    b"nato",     b"navy",     b"needle",   b"neuron",   b"never",    b"newton",
    b"nice",     b"night",    b"nissan",   b"nitro",    b"nixon",    b"north",
    b"oberon",   b"octavia",  b"ohio",     b"olga",     b"open",     b"opus",
    b"orca",     b"oval",     b"owner",    b"page",     b"paint",    b"palma",
    b"parade",   b"parent",   b"parole",   b"paul",     b"peace",    b"pearl",
    b"perform",  b"phoenix",  b"phrase",   b"pierre",   b"pinball",  b"place",
    b"plate",    b"plato",    b"plume",    b"pogo",     b"point",    b"polite",
    b"polka",    b"poncho",   b"powder",   b"prague",   b"press",    b"presto",
    b"pretty",   b"prime",    b"promo",    b"quasi",    b"quest",    b"quick",
    b"quiz",     b"quota",    b"race",     b"rachel",   b"raja",     b"ranger",
    b"region",   b"remark",   b"rent",     b"reward",   b"rhino",    b"ribbon",
    b"rider",    b"road",     b"rodent",   b"round",    b"rubber",   b"ruby",
    b"rufus",    b"sabine",   b"saddle",   b"sailor",   b"saint",    b"salt",
    b"satire",   b"scale",    b"scuba",    b"season",   b"secure",   b"shake",
    b"shallow",  b"shannon",  b"shave",    b"shelf",    b"sherman",  b"shine",
    b"shirt",    b"side",     b"sinatra",  b"sincere",  b"size",     b"slalom",
    b"slow",     b"small",    b"snow",     b"sofia",    b"song",     b"sound",
    b"south",    b"speech",   b"spell",    b"spend",    b"spoon",    b"stage",
    b"stamp",    b"stand",    b"state",    b"stella",   b"stick",    b"sting",
    b"stock",    b"store",    b"sunday",   b"sunset",   b"support",  b"sweden",
    b"swing",    b"tape",     b"think",    b"thomas",   b"tictac",   b"time",
    b"toast",    b"tobacco",  b"tonight",  b"torch",    b"torso",    b"touch",
    b"toyota",   b"trade",    b"tribune",  b"trinity",  b"triton",   b"truck",
    b"trust",    b"type",     b"under",    b"unit",     b"urban",    b"urgent",
    b"user",     b"value",    b"vendor",   b"venice",   b"verona",   b"vibrate",
    b"virgo",    b"visible",  b"vista",    b"vital",    b"voice",    b"vortex",
    b"waiter",   b"watch",    b"wave",     b"weather",  b"wedding",  b"wheel",
    b"whiskey",  b"wisdom",   b"deal",     b"null",     b"nurse",    b"quebec",
    b"reserve",  b"reunion",  b"roof",     b"singer",   b"verbal",   b"amen",
    b"ego",      b"fax",      b"jet",      b"job",      b"rio",      b"ski",
    b"yes"
];

lazy_static! {
    /// Map from words to indices in the MN_WORDS array
    static ref MN_WORD_INDEX: HashMap<&'static [u8], u32> = {
        let mut map = HashMap::new();
        for (i, word) in MN_WORDS.iter().enumerate() {
            map.insert(*word, i as u32);
        }
        map
    };
}

/// Encode the bytes of `src` into a mnemonic string, and write the string to `dest`
///
/// ## Example
/// ```
/// let bytes = [101, 2, 240, 6, 108, 11, 20, 97];
/// let mut dest = Vec::<u8>::new();
///
/// mnemonic::encode(&bytes, &mut dest).unwrap();
/// assert_eq!(dest, &b"digital-apollo-aroma--rival-artist-rebel"[..]);
/// ```
pub fn encode<S, W>(src: S, dest: W) -> io::Result<()>
    where S: AsRef<[u8]>,
          W: Write
{
    encode_with_format(src, MN_FDEFAULT, dest)
}

/// Encode the bytes of `s` with a custom template.
///
/// TODO: Document the template format.
pub fn encode_with_format<S, F, W>(src: S, format: F, mut dest: W) -> io::Result<()>
    where S: AsRef<[u8]>,
          F: AsRef<[u8]>,
          W: Write
{
    let src = src.as_ref();
    let format = format.as_ref();

    let num_words = mn_words_required(src);
    let mut n = 0;
    let mut i = 0; // index within format

    while n < num_words {
        while i < format.len() && !is_ascii_alpha(format[i]) {
            dest.write_all(&[format[i]])?;
            i += 1;
        }
        if i == format.len() {
            i = 0;
            continue
        }
        while is_ascii_alpha(format[i]) {
            i += 1;
        }
        dest.write_all(mn_encode_word(src, n))?;
        n += 1;
    }
    Ok(())
}

/// Encode the bytes of `src` and return the results as a String
///
/// ## Example
/// ```
/// let bytes = [101, 2, 240, 6, 108, 11, 20, 97];
///
/// let s = mnemonic::to_string(&bytes);
/// assert_eq!(s, "digital-apollo-aroma--rival-artist-rebel");
/// ```
pub fn to_string<S: AsRef<[u8]>>(src: S) -> String {
    let mut v = Vec::new();
    encode(src, &mut v).unwrap();
    String::from_utf8(v).unwrap()
}

/// The number of words required to encode data using mnemonic encoding.
fn mn_words_required(src: &[u8]) -> usize {
    (src.len() + 1) * 3 / 4
}

/// Return the `n`th word in the encoding of `src`.
fn mn_encode_word(src: &[u8], n: usize) -> &'static [u8] {
    let offset = n / 3 * 4;
    let mut x = 0;
    for (i, b) in src[offset..].iter().take(4).enumerate() {
        x |= (*b as u32) << (i * 8);
    }

    let mut extra = 0;
    match n % 3 {
        2 => {
            // special case for 24 bits: use one of the 7 3-letter words
            if src.len() - offset == 3 {
                extra = MN_BASE;
            }
            x /= MN_BASE * MN_BASE;
        }
        1 => {
            x /= MN_BASE;
        }
        _ => {}
    }
    MN_WORDS[(x % MN_BASE + extra) as usize]
}

fn is_ascii_alpha(b: u8) -> bool {
    match b {
        b'a'...b'z' |
        b'A'...b'Z' => true,
        _ => false
    }
}

/// Decode the mnemonic string `src` into bytes, and write the bytes to `dest`.
///
/// ## Example
///
/// ```
/// let src = "digital-apollo-aroma--rival-artist-rebel";
///
/// let mut dest = Vec::<u8>::new();
/// mnemonic::decode(src, &mut dest).unwrap();
///
/// assert_eq!(dest, [101, 2, 240, 6, 108, 11, 20, 97]);
/// ```
pub fn decode<S, W>(src: S, mut dest: W) -> Result<usize>
    where S: AsRef<[u8]>,
          W: Write
{
    let mut offset = 0; // Number of bytes decoded so far.
    let mut x = 0u32;   // We decode each 4-byte chunk into this 32-bit value.

    let words = src.as_ref().split(|c| !is_ascii_alpha(*c))
                            .filter(|w| !w.is_empty());
    for word in words {
        let i = *MN_WORD_INDEX.get(word).ok_or(UnrecognizedWord)?;
        mn_decode_word_index(i, &mut x, &mut offset)?;
        if offset % 4 == 0 {
            // Finished decoding this 4-byte chunk.
            dest.write_u32::<LittleEndian>(x)?;
            x = 0;
        }
    }
    // Write any trailing bytes.
    let remainder = offset % 4;
    if remainder > 0 {
        let mut buf = [0; 4];
        LittleEndian::write_u32(&mut buf, x);
        dest.write_all(&buf[..remainder])?;
    }
    mn_decode_finish(x, remainder)?;
    Ok(offset)
}

fn mn_decode_word_index(index: u32, x: &mut u32, offset: &mut usize) -> Result<()> {
    if index >= MN_BASE && *offset % 4 != 2 {
        return Err(UnexpectedRemainderWord)
    }
    match *offset % 4 {
        3 => return Err(DataPastRemainder),
        2 if index >= MN_BASE => {
            // 24-bit remainder
            *x += (index - MN_BASE) * MN_BASE * MN_BASE;
            *offset += 1; // *offset%4 == 3 for next time
        }
        2 => {
            // catch invalid encodings
            if index >= 1625 || (index == 1624 && *x > 1312671) {
                return Err(InvalidEncoding)
            }
            *x += index * MN_BASE * MN_BASE;
            *offset += 2;
        }
        1 => {
            *x += index * MN_BASE;
            *offset += 1;
        }
        0 => {
            *x = index;
            *offset += 1;
        }
        _ => unreachable!()
    }
    Ok(())
}

fn mn_decode_finish(x: u32, remainder: usize) -> Result<()> {
    if (remainder == 2 && x > 0xFFFF) || (remainder == 1 && x > 0xFF) {
        return Err(UnexpectedRemainder)
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;

    #[test]
    fn test_encode() {
        let mut w: Vec<u8> = vec![];
        encode(&[101, 2, 240, 6, 108, 11, 20, 97], &mut w).unwrap();
        let s = str::from_utf8(&w).unwrap();
        assert_eq!(s, "digital-apollo-aroma--rival-artist-rebel");
    }

    #[test]
    fn test_to_string() {
        let src = [101, 2, 240, 6, 108, 11, 20, 97];
        assert_eq!(to_string(&src), "digital-apollo-aroma--rival-artist-rebel");
    }

    #[test]
    fn test_decode() {
        let mut dest: Vec<u8> = vec![];
        let src = "digital-apollo-aroma--rival-artist-rebel";
        decode(src, &mut dest).unwrap();
        assert_eq!(dest, [101, 2, 240, 6, 108, 11, 20, 97]);
    }

    #[test]
    fn test_encode_24bit() {
        let src = [0x01, 0xE2, 0x40];
        assert_eq!(to_string(&src), "consul-quiet-fax");
    }

    #[test]
    fn test_decode_24bit() {
        let mut dest: Vec<u8> = vec![];
        let src = "consul-quiet-fax";
        decode(src, &mut dest).unwrap();
        assert_eq!(dest, [0x01, 0xE2, 0x40]);
    }

    quickcheck! {
        fn quickcheck_round_trip(src: Vec<u8>) -> bool {
            let encoded = to_string(&src);
            let mut decoded = Vec::<u8>::new();
            decode(encoded, &mut decoded).unwrap();
            decoded == src
        }
    }
}
